#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <optional>
#include <unordered_map>
#include <vector>

#include "core/domain/ConnectionKey.h"
#include "core/domain/ProtocolPath.h"

namespace pfl {

using NonTerminalIpContextId = std::uint32_t;
inline constexpr NonTerminalIpContextId kEmptyNonTerminalIpContextId = 0U;
inline constexpr std::size_t kMaxNonTerminalIpContextLevels = kMaxProtocolPathLayers;

enum class NonTerminalIpAddressFamily : std::uint8_t {
    ipv4 = 4,
    ipv6 = 6,
};

struct NonTerminalIpAddress {
    NonTerminalIpAddressFamily family {NonTerminalIpAddressFamily::ipv4};
    std::array<std::uint8_t, 16> bytes {};

    [[nodiscard]] friend constexpr bool operator==(
        const NonTerminalIpAddress&,
        const NonTerminalIpAddress&
    ) = default;
    [[nodiscard]] friend constexpr auto operator<=>(
        const NonTerminalIpAddress&,
        const NonTerminalIpAddress&
    ) = default;

    [[nodiscard]] static constexpr NonTerminalIpAddress ipv4(std::uint32_t address) noexcept;
    [[nodiscard]] static constexpr NonTerminalIpAddress ipv6(
        const std::array<std::uint8_t, 16>& address
    ) noexcept;
};

struct NonTerminalIpLevel {
    NonTerminalIpAddressFamily family {NonTerminalIpAddressFamily::ipv4};
    std::array<std::uint8_t, 16> source {};
    std::array<std::uint8_t, 16> destination {};

    [[nodiscard]] friend constexpr bool operator==(
        const NonTerminalIpLevel&,
        const NonTerminalIpLevel&
    ) = default;
    [[nodiscard]] friend constexpr auto operator<=>(
        const NonTerminalIpLevel&,
        const NonTerminalIpLevel&
    ) = default;

    [[nodiscard]] static constexpr NonTerminalIpLevel ipv4(
        std::uint32_t source,
        std::uint32_t destination
    ) noexcept;
    [[nodiscard]] static constexpr NonTerminalIpLevel ipv6(
        const std::array<std::uint8_t, 16>& source,
        const std::array<std::uint8_t, 16>& destination
    ) noexcept;
};

class NonTerminalIpContextView {
public:
    constexpr NonTerminalIpContextView() noexcept = default;
    constexpr NonTerminalIpContextView(const NonTerminalIpLevel* levels, const std::size_t size) noexcept
        : levels_(levels),
          size_(size) {}

    [[nodiscard]] constexpr std::size_t size() const noexcept {
        return size_;
    }

    [[nodiscard]] constexpr bool empty() const noexcept {
        return size_ == 0U;
    }

    [[nodiscard]] constexpr const NonTerminalIpLevel& operator[](const std::size_t index) const noexcept {
        return levels_[index];
    }

    [[nodiscard]] constexpr const NonTerminalIpLevel* data() const noexcept {
        return levels_;
    }

    [[nodiscard]] constexpr const NonTerminalIpLevel* begin() const noexcept {
        return levels_;
    }

    [[nodiscard]] constexpr const NonTerminalIpLevel* end() const noexcept {
        return levels_ + size_;
    }

private:
    const NonTerminalIpLevel* levels_ {nullptr};
    std::size_t size_ {0U};
};

class NonTerminalIpContext {
public:
    NonTerminalIpContext() = default;
    NonTerminalIpContext(std::initializer_list<NonTerminalIpLevel> levels);
    explicit NonTerminalIpContext(std::vector<NonTerminalIpLevel> levels);

    [[nodiscard]] bool operator==(const NonTerminalIpContext& other) const noexcept;
    [[nodiscard]] friend auto operator<=>(
        const NonTerminalIpContext& lhs,
        const NonTerminalIpContext& rhs
    ) noexcept {
        return lhs.levels_ <=> rhs.levels_;
    }

    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] bool empty() const noexcept;
    [[nodiscard]] const NonTerminalIpLevel& operator[](std::size_t index) const noexcept;
    [[nodiscard]] const std::vector<NonTerminalIpLevel>& levels() const noexcept;
    [[nodiscard]] NonTerminalIpContextView view() const noexcept;

    [[nodiscard]] std::vector<NonTerminalIpLevel>::const_iterator begin() const noexcept;
    [[nodiscard]] std::vector<NonTerminalIpLevel>::const_iterator end() const noexcept;

private:
    std::vector<NonTerminalIpLevel> levels_ {};
};

struct NonTerminalIpContextHash {
    [[nodiscard]] std::size_t operator()(const NonTerminalIpContext& context) const noexcept;
};

struct NonTerminalIpLevelHash {
    [[nodiscard]] std::size_t operator()(const NonTerminalIpLevel& level) const noexcept;
};

class NonTerminalIpContextBuilder {
public:
    [[nodiscard]] bool push(NonTerminalIpLevel level) noexcept;
    [[nodiscard]] bool push_ipv4(std::uint32_t source, std::uint32_t destination) noexcept;
    [[nodiscard]] bool push_ipv6(
        const std::array<std::uint8_t, 16>& source,
        const std::array<std::uint8_t, 16>& destination
    ) noexcept;

    [[nodiscard]] bool full() const noexcept;
    [[nodiscard]] bool overflowed() const noexcept;
    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] bool empty() const noexcept;
    [[nodiscard]] const NonTerminalIpLevel& operator[](std::size_t index) const noexcept;
    [[nodiscard]] NonTerminalIpContextView view() const noexcept;

    [[nodiscard]] std::optional<NonTerminalIpContext> to_context() const;
    void clear() noexcept;

private:
    std::array<NonTerminalIpLevel, kMaxNonTerminalIpContextLevels> levels_ {};
    std::size_t size_ {0U};
    bool overflowed_ {false};
};

class NonTerminalIpContextRegistry {
public:
    [[nodiscard]] NonTerminalIpContextId intern(NonTerminalIpContextView context);
    [[nodiscard]] NonTerminalIpContextId intern(const NonTerminalIpContext& context);
    [[nodiscard]] NonTerminalIpContextId intern(NonTerminalIpContext&& context);
    [[nodiscard]] const NonTerminalIpContext* find(NonTerminalIpContextId id) const noexcept;
    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] const std::vector<NonTerminalIpContext>& contexts() const noexcept;

private:
    [[nodiscard]] NonTerminalIpContextId insert_unique_context(
        NonTerminalIpContext context,
        std::size_t hash
    );

    std::vector<NonTerminalIpContext> contexts_ {};
    std::unordered_map<NonTerminalIpContext, NonTerminalIpContextId, NonTerminalIpContextHash> ids_ {};
    std::unordered_map<std::size_t, std::vector<NonTerminalIpContextId>> ids_by_hash_ {};
};

[[nodiscard]] NonTerminalIpLevel swap_non_terminal_ip_level_direction(NonTerminalIpLevel level) noexcept;
[[nodiscard]] NonTerminalIpContext canonicalize_non_terminal_ip_context(
    NonTerminalIpContextView observed,
    const EndpointKeyV4& terminal_source,
    const EndpointKeyV4& terminal_destination
);
[[nodiscard]] NonTerminalIpContext canonicalize_non_terminal_ip_context(
    NonTerminalIpContextView observed,
    const EndpointKeyV6& terminal_source,
    const EndpointKeyV6& terminal_destination
);

constexpr NonTerminalIpAddress NonTerminalIpAddress::ipv4(const std::uint32_t address) noexcept {
    return NonTerminalIpAddress {
        .family = NonTerminalIpAddressFamily::ipv4,
        .bytes = {
            static_cast<std::uint8_t>((address >> 24U) & 0xffU),
            static_cast<std::uint8_t>((address >> 16U) & 0xffU),
            static_cast<std::uint8_t>((address >> 8U) & 0xffU),
            static_cast<std::uint8_t>(address & 0xffU),
        },
    };
}

constexpr NonTerminalIpAddress NonTerminalIpAddress::ipv6(
    const std::array<std::uint8_t, 16>& address
) noexcept {
    return NonTerminalIpAddress {
        .family = NonTerminalIpAddressFamily::ipv6,
        .bytes = address,
    };
}

constexpr NonTerminalIpLevel NonTerminalIpLevel::ipv4(
    const std::uint32_t source,
    const std::uint32_t destination
) noexcept {
    return NonTerminalIpLevel {
        .family = NonTerminalIpAddressFamily::ipv4,
        .source = NonTerminalIpAddress::ipv4(source).bytes,
        .destination = NonTerminalIpAddress::ipv4(destination).bytes,
    };
}

constexpr NonTerminalIpLevel NonTerminalIpLevel::ipv6(
    const std::array<std::uint8_t, 16>& source,
    const std::array<std::uint8_t, 16>& destination
) noexcept {
    return NonTerminalIpLevel {
        .family = NonTerminalIpAddressFamily::ipv6,
        .source = source,
        .destination = destination,
    };
}

}  // namespace pfl

namespace std {

template <>
struct hash<pfl::NonTerminalIpLevel> {
    [[nodiscard]] size_t operator()(const pfl::NonTerminalIpLevel& level) const noexcept {
        return pfl::NonTerminalIpLevelHash {}(level);
    }
};

template <>
struct hash<pfl::NonTerminalIpContext> {
    [[nodiscard]] size_t operator()(const pfl::NonTerminalIpContext& context) const noexcept {
        return pfl::NonTerminalIpContextHash {}(context);
    }
};

}  // namespace std
