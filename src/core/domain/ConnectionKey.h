#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>

#include "core/domain/Direction.h"
#include "core/domain/FlowKey.h"

namespace pfl {

struct EndpointKeyV4 {
    std::uint32_t addr {0};
    std::uint16_t port {0};

    [[nodiscard]] friend constexpr bool operator==(const EndpointKeyV4&, const EndpointKeyV4&) = default;
    [[nodiscard]] friend constexpr auto operator<=>(const EndpointKeyV4&, const EndpointKeyV4&) = default;
};

struct EndpointKeyV6 {
    std::array<std::uint8_t, 16> addr {};
    std::uint16_t port {0};

    [[nodiscard]] friend constexpr bool operator==(const EndpointKeyV6&, const EndpointKeyV6&) = default;
    [[nodiscard]] friend constexpr auto operator<=>(const EndpointKeyV6&, const EndpointKeyV6&) = default;
};

struct ConnectionKeyV4 {
    EndpointKeyV4 first {};
    EndpointKeyV4 second {};
    ProtocolId protocol {ProtocolId::unknown};

    [[nodiscard]] friend constexpr bool operator==(const ConnectionKeyV4&, const ConnectionKeyV4&) = default;
    [[nodiscard]] friend constexpr auto operator<=>(const ConnectionKeyV4&, const ConnectionKeyV4&) = default;
};

struct ConnectionKeyV6 {
    EndpointKeyV6 first {};
    EndpointKeyV6 second {};
    ProtocolId protocol {ProtocolId::unknown};

    [[nodiscard]] friend constexpr bool operator==(const ConnectionKeyV6&, const ConnectionKeyV6&) = default;
    [[nodiscard]] friend constexpr auto operator<=>(const ConnectionKeyV6&, const ConnectionKeyV6&) = default;
};

struct ConnectionKeyV4Hash {
    [[nodiscard]] std::size_t operator()(const ConnectionKeyV4& key) const noexcept;
};

struct ConnectionKeyV6Hash {
    [[nodiscard]] std::size_t operator()(const ConnectionKeyV6& key) const noexcept;
};

[[nodiscard]] ConnectionKeyV4 make_connection_key(const FlowKeyV4& key) noexcept;
[[nodiscard]] ConnectionKeyV6 make_connection_key(const FlowKeyV6& key) noexcept;

[[nodiscard]] Direction resolve_direction(const ConnectionKeyV4& connection_key, const FlowKeyV4& flow_key) noexcept;
[[nodiscard]] Direction resolve_direction(const ConnectionKeyV6& connection_key, const FlowKeyV6& flow_key) noexcept;

}  // namespace pfl

namespace std {

template <>
struct hash<pfl::ConnectionKeyV4> {
    [[nodiscard]] size_t operator()(const pfl::ConnectionKeyV4& key) const noexcept {
        return pfl::ConnectionKeyV4Hash {}(key);
    }
};

template <>
struct hash<pfl::ConnectionKeyV6> {
    [[nodiscard]] size_t operator()(const pfl::ConnectionKeyV6& key) const noexcept {
        return pfl::ConnectionKeyV6Hash {}(key);
    }
};

}  // namespace std
