#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>

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

// Reuse LayerKey directly so the dissection foundation reports physical path facts
// without creating a competing protocol-path model. Global normalization and
// interning remain outside this subsystem.
using IdentityContribution = LayerKey;

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
