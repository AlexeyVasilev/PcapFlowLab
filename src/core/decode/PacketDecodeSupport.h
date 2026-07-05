#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "core/io/LinkType.h"

namespace pfl::detail {

inline constexpr std::size_t kEthernetHeaderSize = 14;
inline constexpr std::size_t kLinuxSllHeaderSize = 16;
inline constexpr std::size_t kLinuxSll2HeaderSize = 20;
inline constexpr std::size_t kVlanHeaderSize = 4;
inline constexpr std::size_t kLlcHeaderSize = 3;
inline constexpr std::size_t kSnapHeaderSize = 5;
inline constexpr std::size_t kLlcSnapHeaderSize = kLlcHeaderSize + kSnapHeaderSize;
inline constexpr std::size_t kMaxVlanTags = 4;
inline constexpr std::size_t kMplsLabelSize = 4;
inline constexpr std::size_t kMaxMplsLabels = 16;
inline constexpr std::size_t kMaxIpv6ExtensionHeaders = 8;
inline constexpr std::uint16_t kEtherTypeArp = 0x0806U;
inline constexpr std::uint16_t kEtherTypeIpv4 = 0x0800U;
inline constexpr std::uint16_t kEtherTypeIpv6 = 0x86DDU;
inline constexpr std::uint16_t kEtherTypeVlan = 0x8100U;
inline constexpr std::uint16_t kEtherTypeQinq = 0x88A8U;
inline constexpr std::uint16_t kEtherTypeLegacyVlan = 0x9100U;
inline constexpr std::uint16_t kEtherTypeMplsUnicast = 0x8847U;
inline constexpr std::uint16_t kEtherTypeMplsMulticast = 0x8848U;
inline constexpr std::uint16_t kEtherTypePppoeDiscovery = 0x8863U;
inline constexpr std::uint16_t kEtherTypePppoeSession = 0x8864U;
inline constexpr std::uint16_t kEtherTypePbb = 0x88E7U;
inline constexpr std::uint16_t kEtherTypeMacsec = 0x88E5U;
inline constexpr std::uint16_t kArpProtocolTypeIpv4 = 0x0800U;
inline constexpr std::uint16_t kPppProtocolIpv4 = 0x0021U;
inline constexpr std::uint16_t kPppProtocolIpv6 = 0x0057U;
inline constexpr std::uint16_t kIeee8023LengthCutoff = 0x0600U;
inline constexpr std::uint8_t kLlcSnapDsap = 0xaaU;
inline constexpr std::uint8_t kLlcSnapSsap = 0xaaU;
inline constexpr std::uint8_t kLlcUnnumberedInformationControl = 0x03U;
inline constexpr std::uint8_t kIpProtocolIcmp = 1;
inline constexpr std::uint8_t kIpProtocolIgmp = 2;
inline constexpr std::uint8_t kIpProtocolTcp = 6;
inline constexpr std::uint8_t kIpProtocolUdp = 17;
inline constexpr std::uint8_t kIpProtocolRouting = 43;
inline constexpr std::uint8_t kIpProtocolFragment = 44;
inline constexpr std::uint8_t kIpProtocolEsp = 50;
inline constexpr std::uint8_t kIpProtocolAh = 51;
inline constexpr std::uint8_t kIpProtocolIcmpV6 = 58;
inline constexpr std::uint8_t kIpProtocolNoNextHeader = 59;
inline constexpr std::uint8_t kIpProtocolDestinationOptions = 60;
inline constexpr std::uint8_t kIpProtocolHopByHop = 0;
inline constexpr std::size_t kIpv4MinimumHeaderSize = 20;
inline constexpr std::size_t kIpv6HeaderSize = 40;
inline constexpr std::size_t kTransportPortsSize = 4;
inline constexpr std::size_t kTcpMinimumHeaderSize = 20;
inline constexpr std::size_t kUdpHeaderSize = 8;
inline constexpr std::size_t kVxlanHeaderSize = 8U;
inline constexpr std::size_t kGeneveHeaderSize = 8U;
inline constexpr std::size_t kIgmpMinimumHeaderSize = 8;
inline constexpr std::size_t kPppoeHeaderSize = 6U;
inline constexpr std::size_t kPppProtocolFieldSize = 2U;
inline constexpr std::size_t kPbbITagSize = 4U;
inline constexpr std::size_t kMacsecSecTagBaseSize = 6U;
inline constexpr std::size_t kMacsecSciSize = 8U;
inline constexpr std::size_t kMacsecDefaultIcvSize = 16U;
inline constexpr std::uint8_t kIgmpTypeMembershipQuery = 0x11;
inline constexpr std::uint8_t kIgmpTypeV1MembershipReport = 0x12;
inline constexpr std::uint8_t kIgmpTypeV2MembershipReport = 0x16;
inline constexpr std::uint8_t kIgmpTypeLeaveGroup = 0x17;
inline constexpr std::uint8_t kIgmpTypeV3MembershipReport = 0x22;
inline constexpr std::uint16_t kUdpPortVxlan = 4789U;
inline constexpr std::uint16_t kUdpPortGeneve = 6081U;
inline constexpr std::uint16_t kGeneveProtocolTypeEthernet = 0x6558U;
inline constexpr std::uint8_t kVxlanFlagI = 0x08U;

struct LinkLayerPayloadView {
    std::uint16_t protocol_type {0};
    std::size_t payload_offset {0};
    bool is_ethernet {false};
    bool is_linux_cooked {false};
    bool is_ieee_802_3 {false};
    std::uint16_t declared_payload_length {0};
    std::uint16_t cooked_packet_type {0};
    std::uint16_t cooked_hardware_type {0};
};

struct LlcSnapPayloadView {
    bool has_llc {false};
    std::uint8_t available_llc_header_bytes {0};
    std::uint8_t dsap {0};
    std::uint8_t ssap {0};
    std::uint8_t control {0};
    bool llc_header_truncated {false};
    bool has_snap {false};
    std::array<std::uint8_t, 3> oui {};
    std::uint16_t pid {0};
    bool snap_header_truncated {false};
    bool resolved_supported_protocol {false};
    std::uint16_t resolved_protocol_type {0};
    std::size_t resolved_payload_offset {0};
    std::size_t payload_end {0};
    bool payload_length_exceeds_captured {false};
    bool captured_payload_exceeds_declared {false};
};

struct Ipv6PayloadView {
    std::uint8_t next_header {0};
    std::size_t payload_offset {0};
    bool has_fragment_header {false};
};

struct UdpPayloadBounds {
    std::uint16_t datagram_length {0};
    std::size_t payload_offset {0};
    std::size_t payload_length {0};
};

struct Ipv4PacketBounds {
    std::size_t header_length {0};
    std::uint16_t total_length {0};
    std::size_t nominal_packet_end {0};
    std::size_t packet_end {0};
    bool bounds_from_captured_bytes {false};
};

struct IgmpHeaderView {
    std::size_t available_length {0};
    std::uint8_t type {0};
    std::uint8_t max_resp_code {0};
    std::uint16_t checksum {0};
    std::uint32_t group_address {0};
    std::uint16_t group_record_count {0};
    bool has_group_address {false};
    bool is_v3_membership_report {false};
    bool header_truncated {false};
};

struct MplsLabelView {
    std::uint32_t label {0};
    std::uint8_t traffic_class {0};
    bool bottom_of_stack {false};
    std::uint8_t ttl {0};
};

enum class MplsParseStatus : std::uint8_t {
    not_present,
    resolved_inner_ipv4,
    resolved_inner_ipv6,
    resolved_inner_arp,
    label_truncated,
    bottom_of_stack_not_found,
    missing_inner_payload,
    pseudowire_control_word_truncated,
    inner_ethernet_truncated,
    unknown_inner_ether_type,
    unknown_payload,
};

struct EthernetContinuationView {
    LinkLayerPayloadView link_layer {};
    std::optional<std::size_t> bounded_packet_end {};
    bool resolved_supported_protocol {false};
    std::uint16_t resolved_protocol_type {0};
    std::size_t resolved_payload_offset {0};
};

struct VxlanPayloadView {
    std::uint32_t vni {0};
    std::size_t inner_payload_offset {0};
    std::optional<std::size_t> bounded_packet_end {};
    bool has_inner_ethernet {false};
    bool inner_ethernet_truncated {false};
    std::size_t inner_ethernet_offset {0};
    LinkLayerPayloadView inner_ethernet {};
    bool resolved_supported_protocol {false};
    std::uint16_t resolved_protocol_type {0};
    std::size_t resolved_payload_offset {0};
};

struct GenevePayloadView {
    std::uint32_t vni {0};
    std::uint16_t protocol_type {0};
    std::size_t option_length_bytes {0};
    std::size_t inner_payload_offset {0};
    std::optional<std::size_t> bounded_packet_end {};
    bool has_inner_ethernet {false};
    bool inner_ethernet_truncated {false};
    std::size_t inner_ethernet_offset {0};
    LinkLayerPayloadView inner_ethernet {};
    bool resolved_supported_protocol {false};
    std::uint16_t resolved_protocol_type {0};
    std::size_t resolved_payload_offset {0};
};

struct MplsStackView {
    std::array<MplsLabelView, kMaxMplsLabels> labels {};
    std::size_t label_count {0};
    MplsParseStatus status {MplsParseStatus::not_present};
    std::uint16_t inner_protocol_type {0};
    std::size_t inner_payload_offset {0};
    std::optional<std::size_t> bounded_packet_end {};
    bool has_pseudowire_control_word {false};
    std::uint8_t pseudowire_control_word_available_bytes {0};
    std::uint16_t pseudowire_control_flags {0};
    std::uint16_t pseudowire_control_sequence {0};
    bool has_inner_ethernet {false};
    std::size_t inner_ethernet_offset {0};
    LinkLayerPayloadView inner_ethernet {};
};

enum class PbbParseStatus : std::uint8_t {
    not_present,
    resolved_inner_ipv4,
    resolved_inner_ipv6,
    resolved_inner_arp,
    itag_truncated,
    inner_ethernet_truncated,
    unknown_inner_ether_type,
    unknown_payload,
};

enum class MacsecParseStatus : std::uint8_t {
    not_present,
    complete,
    sectag_truncated,
    packet_number_truncated,
    sci_truncated,
    icv_truncated,
};

struct PbbFrameView {
    PbbParseStatus status {PbbParseStatus::not_present};
    std::uint8_t available_itag_bytes {0};
    std::uint8_t pcp {0};
    bool dei {false};
    bool nca {false};
    std::uint8_t reserved {0};
    std::uint32_t isid {0};
    std::uint16_t inner_protocol_type {0};
    std::size_t inner_payload_offset {0};
    std::optional<std::size_t> bounded_packet_end {};
    bool has_inner_ethernet {false};
    std::size_t inner_ethernet_offset {0};
    LinkLayerPayloadView inner_ethernet {};
};

struct MacsecFrameView {
    MacsecParseStatus status {MacsecParseStatus::not_present};
    std::uint8_t available_base_bytes {0};
    std::uint8_t version {0};
    bool es {false};
    bool sc {false};
    bool scb {false};
    bool e {false};
    bool c {false};
    std::uint8_t an {0};
    std::uint8_t short_length {0};
    bool packet_number_present {false};
    std::uint32_t packet_number {0};
    std::uint8_t available_sci_bytes {0};
    std::array<std::uint8_t, 6> sci_system_id {};
    std::uint16_t sci_port_id {0};
    std::size_t protected_payload_offset {0};
    std::size_t protected_payload_length {0};
    std::size_t icv_offset {0};
    std::size_t icv_length {0};
};

struct NetworkPayloadView {
    LinkLayerPayloadView link_layer {};
    std::uint16_t protocol_type {0};
    std::size_t payload_offset {0};
    std::optional<std::size_t> bounded_packet_end {};
    bool has_mpls {false};
    std::uint16_t mpls_ether_type {0};
    MplsStackView mpls {};
    bool has_pbb {false};
    PbbFrameView pbb {};
    bool has_macsec {false};
    MacsecFrameView macsec {};
};

struct PppoePayloadBounds {
    std::size_t declared_length {0};
    std::size_t captured_length {0};
    std::size_t logical_length {0};
    bool declared_exceeds_captured {false};
    bool captured_exceeds_declared {false};
};

struct PppoeSessionPayloadView {
    std::uint16_t ppp_protocol {0};
    std::size_t payload_offset {0};
    std::size_t payload_end {0};
    PppoePayloadBounds bounds {};
};

inline std::uint16_t read_be16(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                      static_cast<std::uint16_t>(bytes[offset + 1]));
}

inline std::uint32_t read_be32(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 3]);
}

inline MacsecFrameView parse_macsec_payload(
    std::span<const std::uint8_t> bytes,
    const std::size_t macsec_offset
) {
    MacsecFrameView view {};
    const auto available_bytes = macsec_offset < bytes.size() ? (bytes.size() - macsec_offset) : 0U;
    view.available_base_bytes = static_cast<std::uint8_t>(std::min<std::size_t>(available_bytes, kMacsecSecTagBaseSize));

    if (view.available_base_bytes >= 1U) {
        const auto tci_an = bytes[macsec_offset];
        view.version = static_cast<std::uint8_t>((tci_an >> 7U) & 0x1U);
        view.es = ((tci_an >> 6U) & 0x1U) != 0U;
        view.sc = ((tci_an >> 5U) & 0x1U) != 0U;
        view.scb = ((tci_an >> 4U) & 0x1U) != 0U;
        view.e = ((tci_an >> 3U) & 0x1U) != 0U;
        view.c = ((tci_an >> 2U) & 0x1U) != 0U;
        view.an = static_cast<std::uint8_t>(tci_an & 0x3U);
    }
    if (view.available_base_bytes >= 2U) {
        view.short_length = bytes[macsec_offset + 1U];
    }

    if (view.available_base_bytes < 2U) {
        view.status = MacsecParseStatus::sectag_truncated;
        return view;
    }
    if (view.available_base_bytes < kMacsecSecTagBaseSize) {
        view.status = MacsecParseStatus::packet_number_truncated;
        return view;
    }

    view.packet_number_present = true;
    view.packet_number = read_be32(bytes, macsec_offset + 2U);
    auto cursor = macsec_offset + kMacsecSecTagBaseSize;

    if (view.sc) {
        const auto available_sci = cursor < bytes.size() ? (bytes.size() - cursor) : 0U;
        view.available_sci_bytes = static_cast<std::uint8_t>(std::min<std::size_t>(available_sci, kMacsecSciSize));
        if (view.available_sci_bytes < kMacsecSciSize) {
            if (view.available_sci_bytes >= 6U) {
                std::copy_n(
                    bytes.begin() + static_cast<std::ptrdiff_t>(cursor),
                    6U,
                    view.sci_system_id.begin()
                );
            }
            if (view.available_sci_bytes >= 8U) {
                view.sci_port_id = read_be16(bytes, cursor + 6U);
            }
            view.status = MacsecParseStatus::sci_truncated;
            return view;
        }

        std::copy_n(
            bytes.begin() + static_cast<std::ptrdiff_t>(cursor),
            6U,
            view.sci_system_id.begin()
        );
        view.sci_port_id = read_be16(bytes, cursor + 6U);
        cursor += kMacsecSciSize;
    }

    view.protected_payload_offset = cursor;
    const auto remaining_bytes = cursor < bytes.size() ? (bytes.size() - cursor) : 0U;
    if (remaining_bytes < kMacsecDefaultIcvSize) {
        view.protected_payload_length = remaining_bytes;
        view.status = MacsecParseStatus::icv_truncated;
        return view;
    }

    view.protected_payload_length = remaining_bytes - kMacsecDefaultIcvSize;
    view.icv_offset = cursor + view.protected_payload_length;
    view.icv_length = kMacsecDefaultIcvSize;
    view.status = MacsecParseStatus::complete;
    return view;
}

inline bool is_vlan_ether_type(const std::uint16_t ether_type) noexcept {
    return ether_type == kEtherTypeVlan ||
           ether_type == kEtherTypeQinq ||
           ether_type == kEtherTypeLegacyVlan;
}

inline bool is_mpls_ether_type(const std::uint16_t ether_type) noexcept {
    return ether_type == kEtherTypeMplsUnicast || ether_type == kEtherTypeMplsMulticast;
}

inline bool is_pppoe_ether_type(const std::uint16_t ether_type) noexcept {
    return ether_type == kEtherTypePppoeDiscovery || ether_type == kEtherTypePppoeSession;
}

inline bool pbb_has_resolved_inner_payload(const PbbParseStatus status) noexcept {
    return status == PbbParseStatus::resolved_inner_ipv4 ||
           status == PbbParseStatus::resolved_inner_ipv6 ||
           status == PbbParseStatus::resolved_inner_arp;
}

inline bool is_supported_snap_pid(const std::uint16_t pid) noexcept {
    return pid == kEtherTypeArp || pid == kEtherTypeIpv4 || pid == kEtherTypeIpv6;
}

inline bool mpls_has_resolved_inner_payload(const MplsParseStatus status) noexcept {
    return status == MplsParseStatus::resolved_inner_ipv4 ||
           status == MplsParseStatus::resolved_inner_ipv6 ||
           status == MplsParseStatus::resolved_inner_arp;
}

inline bool is_ipv6_extension_header(const std::uint8_t next_header) noexcept {
    return next_header == kIpProtocolHopByHop ||
           next_header == kIpProtocolRouting ||
           next_header == kIpProtocolFragment ||
           next_header == kIpProtocolDestinationOptions ||
           next_header == kIpProtocolAh;
}

inline std::optional<LinkLayerPayloadView> parse_link_layer_payload(std::span<const std::uint8_t> bytes,
                                                                    const std::uint32_t data_link_type) {
    if (data_link_type == kLinkTypeEthernet) {
        if (bytes.size() < kEthernetHeaderSize) {
            return std::nullopt;
        }

        LinkLayerPayloadView view {
            .protocol_type = read_be16(bytes, 12U),
            .payload_offset = kEthernetHeaderSize,
            .is_ethernet = true,
        };

        std::size_t vlan_count = 0;
        while (is_vlan_ether_type(view.protocol_type)) {
            if (vlan_count == kMaxVlanTags) {
                return std::nullopt;
            }

            if (bytes.size() < view.payload_offset + kVlanHeaderSize) {
                return std::nullopt;
            }

            view.protocol_type = read_be16(bytes, view.payload_offset + 2U);
            view.payload_offset += kVlanHeaderSize;
            ++vlan_count;
        }

        if (view.protocol_type < kIeee8023LengthCutoff) {
            view.is_ieee_802_3 = true;
            view.declared_payload_length = view.protocol_type;
            view.protocol_type = 0U;
        }

        return view;
    }

    if (data_link_type == kLinkTypeLinuxSll) {
        if (bytes.size() < kLinuxSllHeaderSize) {
            return std::nullopt;
        }

        return LinkLayerPayloadView {
            .protocol_type = read_be16(bytes, 14U),
            .payload_offset = kLinuxSllHeaderSize,
            .is_linux_cooked = true,
            .cooked_packet_type = read_be16(bytes, 0U),
            .cooked_hardware_type = read_be16(bytes, 2U),
        };
    }

    if (data_link_type == kLinkTypeLinuxSll2) {
        if (bytes.size() < kLinuxSll2HeaderSize) {
            return std::nullopt;
        }

        return LinkLayerPayloadView {
            .protocol_type = read_be16(bytes, 0U),
            .payload_offset = kLinuxSll2HeaderSize,
            .is_linux_cooked = true,
            .cooked_packet_type = bytes[10U],
            .cooked_hardware_type = read_be16(bytes, 8U),
        };
    }

    return std::nullopt;
}

inline std::optional<LinkLayerPayloadView> parse_ethernet_payload_at(
    std::span<const std::uint8_t> bytes,
    const std::size_t ethernet_offset
) {
    if (bytes.size() < ethernet_offset + kEthernetHeaderSize) {
        return std::nullopt;
    }

    LinkLayerPayloadView view {
        .protocol_type = read_be16(bytes, ethernet_offset + 12U),
        .payload_offset = ethernet_offset + kEthernetHeaderSize,
        .is_ethernet = true,
    };

    std::size_t vlan_count = 0U;
    while (is_vlan_ether_type(view.protocol_type)) {
        if (vlan_count == kMaxVlanTags) {
            return std::nullopt;
        }

        if (bytes.size() < view.payload_offset + kVlanHeaderSize) {
            return std::nullopt;
        }

        view.protocol_type = read_be16(bytes, view.payload_offset + 2U);
        view.payload_offset += kVlanHeaderSize;
        ++vlan_count;
    }

    if (view.protocol_type < kIeee8023LengthCutoff) {
        view.is_ieee_802_3 = true;
        view.declared_payload_length = view.protocol_type;
        view.protocol_type = 0U;
    }

    return view;
}

inline LlcSnapPayloadView parse_llc_snap_payload(std::span<const std::uint8_t> bytes,
                                                 const std::size_t payload_offset,
                                                 const std::size_t declared_payload_length) {
    LlcSnapPayloadView view {};
    const auto available_payload_length = payload_offset < bytes.size() ? (bytes.size() - payload_offset) : 0U;
    const auto logical_payload_length = std::min(declared_payload_length, available_payload_length);
    view.payload_end = payload_offset + logical_payload_length;
    view.payload_length_exceeds_captured = declared_payload_length > available_payload_length;
    view.captured_payload_exceeds_declared = available_payload_length > declared_payload_length;
    view.available_llc_header_bytes = static_cast<std::uint8_t>(std::min<std::size_t>(logical_payload_length, kLlcHeaderSize));

    if (view.available_llc_header_bytes >= 1U) {
        view.dsap = bytes[payload_offset];
    }
    if (view.available_llc_header_bytes >= 2U) {
        view.ssap = bytes[payload_offset + 1U];
    }
    if (view.available_llc_header_bytes >= 3U) {
        view.control = bytes[payload_offset + 2U];
    }

    if (logical_payload_length < kLlcHeaderSize) {
        view.has_llc = view.available_llc_header_bytes > 0U;
        view.llc_header_truncated = true;
        return view;
    }

    view.has_llc = true;

    if (view.dsap != kLlcSnapDsap ||
        view.ssap != kLlcSnapSsap ||
        view.control != kLlcUnnumberedInformationControl) {
        return view;
    }

    view.has_snap = true;
    if (logical_payload_length < kLlcSnapHeaderSize) {
        view.snap_header_truncated = true;
        return view;
    }

    view.oui = {
        bytes[payload_offset + kLlcHeaderSize],
        bytes[payload_offset + kLlcHeaderSize + 1U],
        bytes[payload_offset + kLlcHeaderSize + 2U],
    };
    view.pid = read_be16(bytes, payload_offset + kLlcHeaderSize + 3U);

    if (is_supported_snap_pid(view.pid)) {
        view.resolved_supported_protocol = true;
        view.resolved_protocol_type = view.pid;
        view.resolved_payload_offset = payload_offset + kLlcSnapHeaderSize;
    }

    return view;
}

inline std::optional<EthernetContinuationView> parse_ethernet_continuation(
    std::span<const std::uint8_t> bytes,
    const std::size_t ethernet_offset
) {
    const auto link_layer = parse_ethernet_payload_at(bytes, ethernet_offset);
    if (!link_layer.has_value()) {
        return std::nullopt;
    }

    EthernetContinuationView view {
        .link_layer = *link_layer,
    };

    if (link_layer->is_ieee_802_3) {
        const auto llc_snap = parse_llc_snap_payload(bytes, link_layer->payload_offset, link_layer->declared_payload_length);
        view.bounded_packet_end = llc_snap.payload_end;
        if (llc_snap.resolved_supported_protocol) {
            view.resolved_supported_protocol = true;
            view.resolved_protocol_type = llc_snap.resolved_protocol_type;
            view.resolved_payload_offset = llc_snap.resolved_payload_offset;
        }
        return view;
    }

    if (link_layer->protocol_type == kEtherTypeArp ||
        link_layer->protocol_type == kEtherTypeIpv4 ||
        link_layer->protocol_type == kEtherTypeIpv6 ||
        link_layer->protocol_type == kEtherTypePppoeDiscovery ||
        link_layer->protocol_type == kEtherTypePppoeSession) {
        view.resolved_supported_protocol = true;
        view.resolved_protocol_type = link_layer->protocol_type;
        view.resolved_payload_offset = link_layer->payload_offset;
    }

    return view;
}

inline std::optional<VxlanPayloadView> parse_vxlan_payload(
    std::span<const std::uint8_t> bytes,
    const std::size_t vxlan_offset,
    const std::size_t vxlan_payload_end
) {
    if (vxlan_offset + kVxlanHeaderSize > vxlan_payload_end ||
        bytes.size() < vxlan_offset + kVxlanHeaderSize) {
        return std::nullopt;
    }

    if (bytes[vxlan_offset] != kVxlanFlagI ||
        bytes[vxlan_offset + 1U] != 0U ||
        bytes[vxlan_offset + 2U] != 0U ||
        bytes[vxlan_offset + 3U] != 0U ||
        bytes[vxlan_offset + 7U] != 0U) {
        return std::nullopt;
    }

    VxlanPayloadView view {};
    view.vni = ((static_cast<std::uint32_t>(bytes[vxlan_offset + 4U]) << 16U) |
                (static_cast<std::uint32_t>(bytes[vxlan_offset + 5U]) << 8U) |
                static_cast<std::uint32_t>(bytes[vxlan_offset + 6U]));
    view.inner_payload_offset = vxlan_offset + kVxlanHeaderSize;
    view.bounded_packet_end = vxlan_payload_end;
    view.inner_ethernet_offset = view.inner_payload_offset;

    if (vxlan_payload_end <= view.inner_payload_offset) {
        view.inner_ethernet_truncated = true;
        return view;
    }

    const auto inner_payload_length = vxlan_payload_end - view.inner_payload_offset;
    if (inner_payload_length < kEthernetHeaderSize) {
        view.has_inner_ethernet = true;
        view.inner_ethernet_truncated = true;
        return view;
    }

    const auto inner_bytes = bytes.subspan(view.inner_payload_offset, inner_payload_length);
    if (const auto continuation = parse_ethernet_continuation(inner_bytes, 0U); continuation.has_value()) {
        view.has_inner_ethernet = true;
        view.inner_ethernet = continuation->link_layer;
        if (continuation->bounded_packet_end.has_value()) {
            view.bounded_packet_end = view.inner_payload_offset + *continuation->bounded_packet_end;
        }
        if (continuation->resolved_supported_protocol) {
            view.resolved_supported_protocol = true;
            view.resolved_protocol_type = continuation->resolved_protocol_type;
            view.resolved_payload_offset = view.inner_payload_offset + continuation->resolved_payload_offset;
        }
        return view;
    }

    return view;
}

inline std::optional<GenevePayloadView> parse_geneve_payload(
    std::span<const std::uint8_t> bytes,
    const std::size_t geneve_offset,
    const std::size_t geneve_payload_end
) {
    if (geneve_offset + kGeneveHeaderSize > geneve_payload_end ||
        bytes.size() < geneve_offset + kGeneveHeaderSize) {
        return std::nullopt;
    }

    const auto first_byte = bytes[geneve_offset];
    const auto version = static_cast<std::uint8_t>((first_byte >> 6U) & 0x03U);
    const auto option_length_words = static_cast<std::size_t>(first_byte & 0x3FU);
    if (version != 0U) {
        return std::nullopt;
    }

    const auto option_length_bytes = option_length_words * 4U;
    const auto header_length = kGeneveHeaderSize + option_length_bytes;
    if (geneve_offset + header_length > geneve_payload_end ||
        bytes.size() < geneve_offset + header_length) {
        return std::nullopt;
    }

    GenevePayloadView view {};
    view.protocol_type = read_be16(bytes, geneve_offset + 2U);
    if (view.protocol_type != kGeneveProtocolTypeEthernet) {
        return std::nullopt;
    }

    view.vni = ((static_cast<std::uint32_t>(bytes[geneve_offset + 4U]) << 16U) |
                (static_cast<std::uint32_t>(bytes[geneve_offset + 5U]) << 8U) |
                static_cast<std::uint32_t>(bytes[geneve_offset + 6U]));
    view.option_length_bytes = option_length_bytes;
    view.inner_payload_offset = geneve_offset + header_length;
    view.bounded_packet_end = geneve_payload_end;
    view.inner_ethernet_offset = view.inner_payload_offset;

    if (geneve_payload_end <= view.inner_payload_offset) {
        view.inner_ethernet_truncated = true;
        return view;
    }

    const auto inner_payload_length = geneve_payload_end - view.inner_payload_offset;
    if (inner_payload_length < kEthernetHeaderSize) {
        view.has_inner_ethernet = true;
        view.inner_ethernet_truncated = true;
        return view;
    }

    const auto inner_bytes = bytes.subspan(view.inner_payload_offset, inner_payload_length);
    if (const auto continuation = parse_ethernet_continuation(inner_bytes, 0U); continuation.has_value()) {
        view.has_inner_ethernet = true;
        view.inner_ethernet = continuation->link_layer;
        if (continuation->bounded_packet_end.has_value()) {
            view.bounded_packet_end = view.inner_payload_offset + *continuation->bounded_packet_end;
        }
        if (continuation->resolved_supported_protocol) {
            view.resolved_supported_protocol = true;
            view.resolved_protocol_type = continuation->resolved_protocol_type;
            view.resolved_payload_offset = view.inner_payload_offset + continuation->resolved_payload_offset;
        }
        return view;
    }

    return view;
}

inline PbbFrameView parse_pbb_payload(
    std::span<const std::uint8_t> bytes,
    const std::size_t pbb_offset
) {
    PbbFrameView view {};
    view.available_itag_bytes = static_cast<std::uint8_t>(std::min<std::size_t>(
        kPbbITagSize,
        pbb_offset < bytes.size() ? (bytes.size() - pbb_offset) : 0U
    ));

    if (view.available_itag_bytes < kPbbITagSize) {
        if (view.available_itag_bytes >= 1U) {
            const auto first_byte = bytes[pbb_offset];
            view.pcp = static_cast<std::uint8_t>((first_byte >> 5U) & 0x7U);
            view.dei = ((first_byte >> 4U) & 0x1U) != 0U;
            view.nca = ((first_byte >> 3U) & 0x1U) != 0U;
            view.reserved = static_cast<std::uint8_t>(first_byte & 0x7U);
        }
        view.status = PbbParseStatus::itag_truncated;
        return view;
    }

    const auto itag = read_be32(bytes, pbb_offset);
    view.pcp = static_cast<std::uint8_t>((itag >> 29U) & 0x7U);
    view.dei = ((itag >> 28U) & 0x1U) != 0U;
    view.nca = ((itag >> 27U) & 0x1U) != 0U;
    view.reserved = static_cast<std::uint8_t>((itag >> 24U) & 0x7U);
    view.isid = itag & 0x00FFFFFFU;

    const auto inner_ethernet_offset = pbb_offset + kPbbITagSize;
    if (const auto continuation = parse_ethernet_continuation(bytes, inner_ethernet_offset); continuation.has_value()) {
        view.has_inner_ethernet = true;
        view.inner_ethernet_offset = inner_ethernet_offset;
        view.inner_ethernet = continuation->link_layer;
        view.bounded_packet_end = continuation->bounded_packet_end;

        if (continuation->resolved_supported_protocol) {
            view.inner_protocol_type = continuation->resolved_protocol_type;
            view.inner_payload_offset = continuation->resolved_payload_offset;
            if (view.inner_protocol_type == kEtherTypeIpv4) {
                view.status = PbbParseStatus::resolved_inner_ipv4;
            } else if (view.inner_protocol_type == kEtherTypeIpv6) {
                view.status = PbbParseStatus::resolved_inner_ipv6;
            } else if (view.inner_protocol_type == kEtherTypeArp) {
                view.status = PbbParseStatus::resolved_inner_arp;
            } else {
                view.status = PbbParseStatus::unknown_payload;
            }
        } else if (!continuation->link_layer.is_ieee_802_3 &&
                   continuation->link_layer.protocol_type >= kIeee8023LengthCutoff) {
            view.status = PbbParseStatus::unknown_inner_ether_type;
        } else {
            view.status = PbbParseStatus::unknown_payload;
        }
        return view;
    }

    view.has_inner_ethernet = true;
    view.inner_ethernet_offset = inner_ethernet_offset;
    view.status = PbbParseStatus::inner_ethernet_truncated;
    return view;
}

inline bool is_plausible_mpls_pseudowire_control_word(
    std::span<const std::uint8_t> bytes,
    const std::size_t offset
) noexcept {
    return bytes.size() >= offset + 2U &&
           bytes[offset] == 0U &&
           bytes[offset + 1U] == 0U;
}

inline MplsStackView parse_mpls_stack(std::span<const std::uint8_t> bytes, std::size_t offset) {
    MplsStackView stack {};

    for (std::size_t label_index = 0; label_index < kMaxMplsLabels; ++label_index) {
        if (offset >= bytes.size()) {
            stack.status = MplsParseStatus::bottom_of_stack_not_found;
            return stack;
        }

        if (bytes.size() < offset + kMplsLabelSize) {
            stack.status = MplsParseStatus::label_truncated;
            return stack;
        }

        const auto entry = read_be32(bytes, offset);
        const auto label = static_cast<std::uint32_t>((entry >> 12U) & 0x000FFFFFU);
        const auto traffic_class = static_cast<std::uint8_t>((entry >> 9U) & 0x7U);
        const auto bottom_of_stack = ((entry >> 8U) & 0x1U) != 0U;
        const auto ttl = static_cast<std::uint8_t>(entry & 0xFFU);

        stack.labels[stack.label_count] = MplsLabelView {
            .label = label,
            .traffic_class = traffic_class,
            .bottom_of_stack = bottom_of_stack,
            .ttl = ttl,
        };
        ++stack.label_count;
        offset += kMplsLabelSize;

        if (!bottom_of_stack) {
            continue;
        }

        stack.inner_payload_offset = offset;
        if (offset >= bytes.size()) {
            stack.status = MplsParseStatus::missing_inner_payload;
            return stack;
        }

        const auto version_nibble = static_cast<std::uint8_t>(bytes[offset] >> 4U);
        if (version_nibble == 4U) {
            stack.inner_protocol_type = kEtherTypeIpv4;
            stack.status = MplsParseStatus::resolved_inner_ipv4;
            return stack;
        }
        if (version_nibble == 6U) {
            stack.inner_protocol_type = kEtherTypeIpv6;
            stack.status = MplsParseStatus::resolved_inner_ipv6;
            return stack;
        }

        if (is_plausible_mpls_pseudowire_control_word(bytes, offset) && bytes.size() < offset + 4U) {
            stack.has_pseudowire_control_word = true;
            stack.pseudowire_control_word_available_bytes = static_cast<std::uint8_t>(bytes.size() - offset);
            if (stack.pseudowire_control_word_available_bytes >= 2U) {
                stack.pseudowire_control_flags = read_be16(bytes, offset);
            }
            stack.status = MplsParseStatus::pseudowire_control_word_truncated;
            return stack;
        }

        if (is_plausible_mpls_pseudowire_control_word(bytes, offset)) {
            if (const auto continuation = parse_ethernet_continuation(bytes, offset + 4U); continuation.has_value()) {
                stack.has_pseudowire_control_word = true;
                stack.pseudowire_control_word_available_bytes = 4U;
                stack.pseudowire_control_flags = read_be16(bytes, offset);
                stack.pseudowire_control_sequence = read_be16(bytes, offset + 2U);
                stack.has_inner_ethernet = true;
                stack.inner_ethernet_offset = offset + 4U;
                stack.inner_ethernet = continuation->link_layer;
                stack.bounded_packet_end = continuation->bounded_packet_end;

                if (continuation->resolved_supported_protocol) {
                    stack.inner_protocol_type = continuation->resolved_protocol_type;
                    stack.inner_payload_offset = continuation->resolved_payload_offset;
                    if (stack.inner_protocol_type == kEtherTypeIpv4) {
                        stack.status = MplsParseStatus::resolved_inner_ipv4;
                    } else if (stack.inner_protocol_type == kEtherTypeIpv6) {
                        stack.status = MplsParseStatus::resolved_inner_ipv6;
                    } else if (stack.inner_protocol_type == kEtherTypeArp) {
                        stack.status = MplsParseStatus::resolved_inner_arp;
                    } else {
                        stack.status = MplsParseStatus::unknown_payload;
                    }
                } else if (!continuation->link_layer.is_ieee_802_3 &&
                           continuation->link_layer.protocol_type >= kIeee8023LengthCutoff) {
                    stack.status = MplsParseStatus::unknown_inner_ether_type;
                } else {
                    stack.status = MplsParseStatus::unknown_payload;
                }
                return stack;
            }

            if (bytes.size() >= offset + 4U) {
                stack.has_pseudowire_control_word = true;
                stack.pseudowire_control_word_available_bytes = 4U;
                stack.pseudowire_control_flags = read_be16(bytes, offset);
                stack.pseudowire_control_sequence = read_be16(bytes, offset + 2U);
                stack.has_inner_ethernet = true;
                stack.inner_ethernet_offset = offset + 4U;
                stack.status = MplsParseStatus::inner_ethernet_truncated;
                return stack;
            }
        }

        if (const auto continuation = parse_ethernet_continuation(bytes, offset); continuation.has_value()) {
            stack.has_inner_ethernet = true;
            stack.inner_ethernet_offset = offset;
            stack.inner_ethernet = continuation->link_layer;
            stack.bounded_packet_end = continuation->bounded_packet_end;

            if (continuation->resolved_supported_protocol) {
                stack.inner_protocol_type = continuation->resolved_protocol_type;
                stack.inner_payload_offset = continuation->resolved_payload_offset;
                if (stack.inner_protocol_type == kEtherTypeIpv4) {
                    stack.status = MplsParseStatus::resolved_inner_ipv4;
                } else if (stack.inner_protocol_type == kEtherTypeIpv6) {
                    stack.status = MplsParseStatus::resolved_inner_ipv6;
                } else if (stack.inner_protocol_type == kEtherTypeArp) {
                    stack.status = MplsParseStatus::resolved_inner_arp;
                } else {
                    stack.status = MplsParseStatus::unknown_payload;
                }
            } else if (!continuation->link_layer.is_ieee_802_3 &&
                       continuation->link_layer.protocol_type >= kIeee8023LengthCutoff) {
                stack.status = MplsParseStatus::unknown_inner_ether_type;
            } else {
                stack.status = MplsParseStatus::unknown_payload;
            }
            return stack;
        }

        if (bytes.size() < offset + kEthernetHeaderSize) {
            stack.has_inner_ethernet = true;
            stack.inner_ethernet_offset = offset;
            stack.status = MplsParseStatus::inner_ethernet_truncated;
            return stack;
        }

        stack.status = MplsParseStatus::unknown_payload;
        return stack;
    }

    stack.status = MplsParseStatus::bottom_of_stack_not_found;
    return stack;
}

inline std::optional<PppoePayloadBounds> parse_pppoe_payload_bounds(
    std::span<const std::uint8_t> bytes,
    const std::size_t pppoe_offset
) {
    if (bytes.size() < pppoe_offset + kPppoeHeaderSize) {
        return std::nullopt;
    }

    const auto payload_offset = pppoe_offset + kPppoeHeaderSize;
    const auto available_payload_length = bytes.size() - payload_offset;
    const auto declared_payload_length = static_cast<std::size_t>(read_be16(bytes, pppoe_offset + 4U));
    const auto logical_payload_length = std::min(declared_payload_length, available_payload_length);

    return PppoePayloadBounds {
        .declared_length = declared_payload_length,
        .captured_length = available_payload_length,
        .logical_length = logical_payload_length,
        .declared_exceeds_captured = declared_payload_length > available_payload_length,
        .captured_exceeds_declared = available_payload_length > declared_payload_length,
    };
}

inline std::optional<PppoeSessionPayloadView> parse_pppoe_session_payload(
    std::span<const std::uint8_t> bytes,
    const std::size_t pppoe_offset
) {
    if (bytes.size() < pppoe_offset + kPppoeHeaderSize) {
        return std::nullopt;
    }

    const auto version_type = bytes[pppoe_offset];
    const auto version = static_cast<std::uint8_t>(version_type >> 4U);
    const auto type = static_cast<std::uint8_t>(version_type & 0x0FU);
    const auto code = bytes[pppoe_offset + 1U];
    const auto payload_offset = pppoe_offset + kPppoeHeaderSize;
    const auto bounds = parse_pppoe_payload_bounds(bytes, pppoe_offset);

    if (!bounds.has_value() ||
        version != 1U ||
        type != 1U ||
        code != 0U ||
        bounds->logical_length < kPppProtocolFieldSize) {
        return std::nullopt;
    }

    if (bytes.size() < payload_offset + kPppProtocolFieldSize) {
        return std::nullopt;
    }

    return PppoeSessionPayloadView {
        .ppp_protocol = read_be16(bytes, payload_offset),
        .payload_offset = payload_offset + kPppProtocolFieldSize,
        .payload_end = payload_offset + bounds->logical_length,
        .bounds = *bounds,
    };
}

inline void resolve_pppoe_inner_payload(std::span<const std::uint8_t> bytes, NetworkPayloadView& view) {
    if (view.protocol_type != kEtherTypePppoeSession) {
        return;
    }

    if (const auto pppoe = parse_pppoe_session_payload(bytes, view.payload_offset); pppoe.has_value()) {
        if (pppoe->ppp_protocol == kPppProtocolIpv4) {
            view.protocol_type = kEtherTypeIpv4;
            view.payload_offset = pppoe->payload_offset;
            view.bounded_packet_end = pppoe->payload_end;
        } else if (pppoe->ppp_protocol == kPppProtocolIpv6) {
            view.protocol_type = kEtherTypeIpv6;
            view.payload_offset = pppoe->payload_offset;
            view.bounded_packet_end = pppoe->payload_end;
        }
    }
}

inline std::optional<NetworkPayloadView> parse_network_payload(std::span<const std::uint8_t> bytes,
                                                               const std::uint32_t data_link_type) {
    const auto envelope = parse_link_layer_payload(bytes, data_link_type);
    if (!envelope.has_value()) {
        return std::nullopt;
    }

    NetworkPayloadView view {};
    view.link_layer = *envelope;
    view.protocol_type = envelope->protocol_type;
    view.payload_offset = envelope->payload_offset;

    if (envelope->is_ieee_802_3) {
        const auto llc_snap = parse_llc_snap_payload(bytes, envelope->payload_offset, envelope->declared_payload_length);
        view.bounded_packet_end = llc_snap.payload_end;
        if (!llc_snap.resolved_supported_protocol) {
            view.protocol_type = 0U;
            return view;
        }

        view.protocol_type = llc_snap.resolved_protocol_type;
        view.payload_offset = llc_snap.resolved_payload_offset;
        return view;
    }

    if (!is_mpls_ether_type(envelope->protocol_type)) {
        if (envelope->protocol_type == kEtherTypePbb) {
            view.has_pbb = true;
            view.pbb = parse_pbb_payload(bytes, envelope->payload_offset);
            if (pbb_has_resolved_inner_payload(view.pbb.status)) {
                view.protocol_type = view.pbb.inner_protocol_type;
                view.payload_offset = view.pbb.inner_payload_offset;
                if (view.pbb.bounded_packet_end.has_value()) {
                    view.bounded_packet_end = view.pbb.bounded_packet_end;
                }
                return view;
            }

            view.protocol_type = 0U;
            if (view.pbb.bounded_packet_end.has_value()) {
                view.bounded_packet_end = view.pbb.bounded_packet_end;
            }
            return view;
        }

        if (envelope->protocol_type == kEtherTypeMacsec) {
            view.has_macsec = true;
            view.macsec = parse_macsec_payload(bytes, envelope->payload_offset);
            view.protocol_type = 0U;
            return view;
        }

        resolve_pppoe_inner_payload(bytes, view);
        return view;
    }

    view.has_mpls = true;
    view.mpls_ether_type = envelope->protocol_type;
    view.mpls = parse_mpls_stack(bytes, envelope->payload_offset);

    if (mpls_has_resolved_inner_payload(view.mpls.status)) {
        view.protocol_type = view.mpls.inner_protocol_type;
        view.payload_offset = view.mpls.inner_payload_offset;
        if (view.mpls.bounded_packet_end.has_value()) {
            view.bounded_packet_end = view.mpls.bounded_packet_end;
        }
    } else {
        view.protocol_type = 0;
        return view;
    }

    resolve_pppoe_inner_payload(bytes, view);

    return view;
}

inline std::optional<Ipv6PayloadView> parse_ipv6_payload(std::span<const std::uint8_t> bytes, const std::size_t ipv6_offset) {
    if (bytes.size() < ipv6_offset + kIpv6HeaderSize) {
        return std::nullopt;
    }

    std::uint8_t next_header = bytes[ipv6_offset + 6U];
    std::size_t payload_offset = ipv6_offset + kIpv6HeaderSize;
    bool has_fragment_header = false;

    for (std::size_t extension_count = 0; extension_count < kMaxIpv6ExtensionHeaders; ++extension_count) {
        if (!is_ipv6_extension_header(next_header)) {
            return Ipv6PayloadView {
                .next_header = next_header,
                .payload_offset = payload_offset,
                .has_fragment_header = has_fragment_header,
            };
        }

        if (bytes.size() < payload_offset + 2U) {
            return std::nullopt;
        }

        if (next_header == kIpProtocolFragment) {
            if (bytes.size() < payload_offset + 8U) {
                return std::nullopt;
            }

            has_fragment_header = true;
            next_header = bytes[payload_offset];
            payload_offset += 8U;
            continue;
        }

        std::size_t header_length = 0;
        if (next_header == kIpProtocolAh) {
            header_length = static_cast<std::size_t>(bytes[payload_offset + 1U] + 2U) * 4U;
        } else {
            header_length = static_cast<std::size_t>(bytes[payload_offset + 1U] + 1U) * 8U;
        }

        if (header_length < 8U || bytes.size() < payload_offset + header_length) {
            return std::nullopt;
        }

        next_header = bytes[payload_offset];
        payload_offset += header_length;
    }

    return std::nullopt;
}

inline std::optional<Ipv4PacketBounds> parse_ipv4_packet_bounds(std::span<const std::uint8_t> bytes,
                                                                const std::size_t ipv4_offset) {
    if (bytes.size() < ipv4_offset + kIpv4MinimumHeaderSize) {
        return std::nullopt;
    }

    const auto version = static_cast<std::uint8_t>(bytes[ipv4_offset] >> 4U);
    const auto ihl = static_cast<std::size_t>((bytes[ipv4_offset] & 0x0FU) * 4U);
    const auto total_length = read_be16(bytes, ipv4_offset + 2U);
    if (version != 4U || ihl < kIpv4MinimumHeaderSize) {
        return std::nullopt;
    }

    if (bytes.size() < ipv4_offset + ihl) {
        return std::nullopt;
    }

    const bool bounds_from_captured_bytes = total_length == 0U;
    if (!bounds_from_captured_bytes && total_length < ihl) {
        return std::nullopt;
    }

    const auto nominal_packet_end = bounds_from_captured_bytes
        ? bytes.size()
        : (ipv4_offset + static_cast<std::size_t>(total_length));
    const auto packet_end = std::min(nominal_packet_end, bytes.size());
    if (packet_end < ipv4_offset + ihl) {
        return std::nullopt;
    }

    return Ipv4PacketBounds {
        .header_length = ihl,
        .total_length = total_length,
        .nominal_packet_end = nominal_packet_end,
        .packet_end = packet_end,
        .bounds_from_captured_bytes = bounds_from_captured_bytes,
    };
}

inline std::optional<UdpPayloadBounds> parse_udp_payload_bounds(std::span<const std::uint8_t> bytes,
                                                                const std::size_t udp_offset,
                                                                const std::size_t nominal_packet_end) {
    const auto packet_end = std::min(nominal_packet_end, bytes.size());
    if (udp_offset + kUdpHeaderSize > packet_end) {
        return std::nullopt;
    }

    const auto udp_length = static_cast<std::size_t>(read_be16(bytes, udp_offset + 4U));
    if (udp_length < kUdpHeaderSize || udp_offset + udp_length > nominal_packet_end) {
        return std::nullopt;
    }

    const auto payload_offset = udp_offset + kUdpHeaderSize;
    const auto available_payload_length = (packet_end > payload_offset) ? (packet_end - payload_offset) : 0U;
    return UdpPayloadBounds {
        .datagram_length = static_cast<std::uint16_t>(udp_length),
        .payload_offset = payload_offset,
        .payload_length = std::min(udp_length - kUdpHeaderSize, available_payload_length),
    };
}

inline std::optional<IgmpHeaderView> parse_igmp_header(std::span<const std::uint8_t> bytes,
                                                       const std::size_t igmp_offset,
                                                       const std::size_t packet_end) {
    if (igmp_offset >= bytes.size() || igmp_offset >= packet_end) {
        return std::nullopt;
    }

    const auto available_length = std::min(packet_end - igmp_offset, bytes.size() - igmp_offset);
    IgmpHeaderView header {
        .available_length = available_length,
        .type = bytes[igmp_offset],
        .header_truncated = available_length < kIgmpMinimumHeaderSize,
    };

    if (available_length >= 2U) {
        header.max_resp_code = bytes[igmp_offset + 1U];
    }
    if (available_length >= 4U) {
        header.checksum = read_be16(bytes, igmp_offset + 2U);
    }
    if (available_length >= kIgmpMinimumHeaderSize) {
        header.is_v3_membership_report = header.type == kIgmpTypeV3MembershipReport;
        if (header.is_v3_membership_report) {
            header.group_record_count = read_be16(bytes, igmp_offset + 6U);
        } else {
            header.group_address = read_be32(bytes, igmp_offset + 4U);
            header.has_group_address = true;
        }
    }

    return header;
}

inline std::uint32_t igmp_effective_group_address(const IgmpHeaderView& header,
                                                  const std::uint32_t ipv4_destination) noexcept {
    if (header.has_group_address && header.group_address != 0U) {
        return header.group_address;
    }

    return ipv4_destination;
}

}  // namespace pfl::detail
