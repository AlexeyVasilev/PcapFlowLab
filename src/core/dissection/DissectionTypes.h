#pragma once

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

struct Ipv4Facts {
    std::uint8_t protocol {0U};
    std::uint16_t total_length {0U};
    std::size_t header_length {0U};
    std::uint32_t src_addr_v4 {0U};
    std::uint32_t dst_addr_v4 {0U};
    bool is_fragmented {false};
    bool more_fragments {false};
    std::uint16_t fragment_offset_units {0U};

    [[nodiscard]] friend constexpr bool operator==(const Ipv4Facts&, const Ipv4Facts&) = default;
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

using LayerFacts = std::variant<std::monostate, EthernetFacts, VlanFacts, ArpFacts, Ipv4Facts, TcpFacts, UdpFacts>;

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
