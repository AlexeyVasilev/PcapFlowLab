#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <variant>

#include "core/domain/ProtocolId.h"
#include "core/domain/ProtocolPath.h"

namespace pfl::dissection {

enum class ByteSourceKind : std::uint8_t {
    captured_frame = 0,
};

struct ByteSourceId {
    ByteSourceKind kind {ByteSourceKind::captured_frame};
    std::uint32_t value {0};

    [[nodiscard]] friend constexpr bool operator==(const ByteSourceId&, const ByteSourceId&) = default;
    [[nodiscard]] friend constexpr auto operator<=>(const ByteSourceId&, const ByteSourceId&) = default;

    [[nodiscard]] static constexpr ByteSourceId captured_frame(const std::uint32_t value = 0U) noexcept {
        return ByteSourceId {
            .kind = ByteSourceKind::captured_frame,
            .value = value,
        };
    }
};

class ByteRange {
public:
    constexpr ByteRange() noexcept = default;

    [[nodiscard]] static std::optional<ByteRange> from_begin_end(std::size_t begin, std::size_t end) noexcept;
    [[nodiscard]] static std::optional<ByteRange> from_begin_and_length(
        std::size_t begin,
        std::size_t length
    ) noexcept;

    [[nodiscard]] constexpr std::size_t begin() const noexcept {
        return begin_;
    }

    [[nodiscard]] constexpr std::size_t end() const noexcept {
        return end_;
    }

    [[nodiscard]] constexpr std::size_t length() const noexcept {
        return end_ - begin_;
    }

    [[nodiscard]] constexpr bool empty() const noexcept {
        return begin_ == end_;
    }

    [[nodiscard]] friend constexpr bool operator==(const ByteRange&, const ByteRange&) = default;
    [[nodiscard]] friend constexpr auto operator<=>(const ByteRange&, const ByteRange&) = default;

private:
    constexpr ByteRange(const std::size_t begin, const std::size_t end) noexcept
        : begin_(begin)
        , end_(end) {}

    std::size_t begin_ {0U};
    std::size_t end_ {0U};
};

enum class SelectorDomain : std::uint8_t {
    link_type = 0,
    ether_type,
    llc_snap_pid,
    ppp_protocol,
    ip_protocol,
    ipv6_next_header,
    gre_protocol_type,
    udp_destination_port_candidate,
    count,
};

struct ProtocolSelector {
    SelectorDomain domain {SelectorDomain::link_type};
    std::uint32_t value {0U};

    [[nodiscard]] friend constexpr bool operator==(const ProtocolSelector&, const ProtocolSelector&) = default;
    [[nodiscard]] friend constexpr auto operator<=>(const ProtocolSelector&, const ProtocolSelector&) = default;
};

enum class ParseStatus : std::uint8_t {
    complete = 0,
    truncated,
    malformed,
    unsupported_variant,
    opaque,
};

enum class StopReason : std::uint8_t {
    none = 0,
    terminal_protocol,
    no_payload,
    unknown_next_protocol,
    unrecognized_payload,
    encrypted_payload,
    needs_reassembly,
    unsupported_variant,
    malformed,
    truncated,
    depth_limit,
};

enum class DissectionAddressFamily : std::uint8_t {
    unknown = 0,
    ipv4,
    ipv6,
};

enum class DissectionLayerKind : std::uint16_t {
    unknown = 0,
    ethernet_ii,
    ieee8023,
    vlan,
    arp,
    ipv4,
    ipv6,
    ipv6_hop_by_hop,
    ipv6_routing,
    ipv6_destination_options,
    ipv6_fragment,
    ah,
    esp,
    icmp,
    icmpv6,
    igmp,
    tcp,
    udp,
    sctp,
};

struct BoundedByteRange {
    ByteRange declared {};
    ByteRange captured {};

    [[nodiscard]] friend constexpr bool operator==(const BoundedByteRange&, const BoundedByteRange&) = default;
};

struct LayerBounds {
    ByteSourceId source_id {};
    BoundedByteRange full {};
    BoundedByteRange header {};
    std::optional<BoundedByteRange> payload {};

    [[nodiscard]] friend constexpr bool operator==(const LayerBounds&, const LayerBounds&) = default;
};

struct EthernetFacts {
    std::uint16_t protocol_type {0U};
    bool is_ieee_802_3 {false};

    [[nodiscard]] friend constexpr bool operator==(const EthernetFacts&, const EthernetFacts&) = default;
};

struct VlanFacts {
    std::uint16_t tci {0U};
    std::uint16_t encapsulated_ether_type {0U};

    [[nodiscard]] friend constexpr bool operator==(const VlanFacts&, const VlanFacts&) = default;
};

struct ArpFacts {
    std::uint16_t hardware_type {0U};
    std::uint16_t protocol_type {0U};
    std::uint8_t hardware_size {0U};
    std::uint8_t protocol_size {0U};
    std::uint16_t opcode {0U};
    bool has_sender_ipv4 {false};
    bool has_target_ipv4 {false};
    std::uint32_t sender_ipv4 {0U};
    std::uint32_t target_ipv4 {0U};

    [[nodiscard]] friend constexpr bool operator==(const ArpFacts&, const ArpFacts&) = default;
};

enum class Ipv4OptionsParseStatus : std::uint8_t {
    not_present = 0,
    well_formed,
    malformed,
};

struct Ipv4OptionsFacts {
    Ipv4OptionsParseStatus status {Ipv4OptionsParseStatus::not_present};
    std::uint8_t options_length {0U};
    std::uint8_t parsed_option_count {0U};
    std::uint8_t nop_count {0U};
    bool has_end_of_list {false};
    bool has_nonzero_padding {false};
    bool has_router_alert {false};
    std::uint16_t router_alert_value {0U};
    bool has_malformed_offset {false};
    std::uint8_t malformed_offset {0U};

    [[nodiscard]] friend constexpr bool operator==(const Ipv4OptionsFacts&, const Ipv4OptionsFacts&) = default;
};

struct Ipv4Facts {
    std::uint8_t protocol {0U};
    std::uint16_t total_length {0U};
    std::size_t header_length {0U};
    std::uint32_t src_addr_v4 {0U};
    std::uint32_t dst_addr_v4 {0U};
    bool is_fragmented {false};
    bool more_fragments {false};
    std::uint16_t fragment_offset_units {0U};
    Ipv4OptionsFacts options {};

    [[nodiscard]] friend constexpr bool operator==(const Ipv4Facts&, const Ipv4Facts&) = default;
};

struct Ipv6Facts {
    std::uint8_t next_header {0U};
    std::uint16_t payload_length {0U};
    std::array<std::uint8_t, 16> src_addr_v6 {};
    std::array<std::uint8_t, 16> dst_addr_v6 {};
    bool has_fragment_header {false};
    bool more_fragments {false};
    std::uint16_t fragment_offset_units {0U};
    bool is_atomic_fragment {false};

    [[nodiscard]] friend constexpr bool operator==(const Ipv6Facts&, const Ipv6Facts&) = default;
};

struct Ipv6ExtensionFacts {
    DissectionLayerKind kind {DissectionLayerKind::unknown};
    std::uint8_t next_header {0U};
    std::size_t header_length {0U};

    [[nodiscard]] friend constexpr bool operator==(const Ipv6ExtensionFacts&, const Ipv6ExtensionFacts&) = default;
};

struct Ipv6FragmentFacts {
    std::uint8_t next_header {0U};
    std::size_t header_length {0U};
    std::uint16_t fragment_offset_units {0U};
    bool more_fragments {false};
    bool is_atomic_fragment {false};

    [[nodiscard]] friend constexpr bool operator==(const Ipv6FragmentFacts&, const Ipv6FragmentFacts&) = default;
};

struct AhFacts {
    std::uint8_t next_header {0U};
    std::uint8_t payload_length_field {0U};
    std::uint16_t reserved {0U};
    std::uint32_t spi {0U};
    std::uint32_t sequence_number {0U};
    std::uint16_t header_length {0U};
    std::uint16_t icv_length {0U};

    [[nodiscard]] friend constexpr bool operator==(const AhFacts&, const AhFacts&) = default;
};

struct EspFacts {
    std::uint32_t spi {0U};
    std::uint32_t sequence_number {0U};

    [[nodiscard]] friend constexpr bool operator==(const EspFacts&, const EspFacts&) = default;
};

struct IcmpFacts {
    std::uint8_t type {0U};
    std::uint8_t code {0U};
    std::uint16_t checksum {0U};

    [[nodiscard]] friend constexpr bool operator==(const IcmpFacts&, const IcmpFacts&) = default;
};

struct Icmpv6Facts {
    std::uint8_t type {0U};
    std::uint8_t code {0U};
    std::uint16_t checksum {0U};

    [[nodiscard]] friend constexpr bool operator==(const Icmpv6Facts&, const Icmpv6Facts&) = default;
};

struct IgmpFacts {
    std::uint8_t type {0U};
    std::uint8_t code {0U};
    std::uint16_t checksum {0U};
    std::uint32_t group_or_control {0U};
    std::uint32_t effective_destination_v4 {0U};
    bool has_effective_destination_v4 {false};

    [[nodiscard]] friend constexpr bool operator==(const IgmpFacts&, const IgmpFacts&) = default;
};

struct TcpFacts {
    std::uint16_t src_port {0U};
    std::uint16_t dst_port {0U};
    std::uint8_t flags {0U};

    [[nodiscard]] friend constexpr bool operator==(const TcpFacts&, const TcpFacts&) = default;
};

struct UdpFacts {
    std::uint16_t src_port {0U};
    std::uint16_t dst_port {0U};
    std::uint16_t datagram_length {0U};

    [[nodiscard]] friend constexpr bool operator==(const UdpFacts&, const UdpFacts&) = default;
};

struct SctpFacts {
    std::uint16_t src_port {0U};
    std::uint16_t dst_port {0U};
    std::uint32_t verification_tag {0U};
    std::uint32_t checksum {0U};

    [[nodiscard]] friend constexpr bool operator==(const SctpFacts&, const SctpFacts&) = default;
};

using LayerFacts = std::variant<
    std::monostate,
    EthernetFacts,
    VlanFacts,
    ArpFacts,
    Ipv4Facts,
    Ipv6Facts,
    Ipv6ExtensionFacts,
    Ipv6FragmentFacts,
    AhFacts,
    EspFacts,
    IcmpFacts,
    Icmpv6Facts,
    IgmpFacts,
    TcpFacts,
    UdpFacts,
    SctpFacts>;

enum class TerminalDisposition : std::uint8_t {
    none = 0,
    flow_candidate,
    recognized_non_flow,
};

inline constexpr std::size_t selector_domain_count = static_cast<std::size_t>(SelectorDomain::count);

inline std::optional<ByteRange> ByteRange::from_begin_end(const std::size_t begin, const std::size_t end) noexcept {
    if (end < begin) {
        return std::nullopt;
    }

    return ByteRange {begin, end};
}

inline std::optional<ByteRange> ByteRange::from_begin_and_length(
    const std::size_t begin,
    const std::size_t length
) noexcept {
    const auto end = begin + length;
    if (end < begin) {
        return std::nullopt;
    }

    return ByteRange {begin, end};
}

}  // namespace pfl::dissection
