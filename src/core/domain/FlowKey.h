#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>

#include "core/domain/ProtocolId.h"

namespace pfl {

namespace detail {

[[nodiscard]] inline std::size_t hash_combine(std::size_t seed, std::size_t value) noexcept {
    return seed ^ (value + static_cast<std::size_t>(0x9e3779b97f4a7c15ULL) + (seed << 6U) + (seed >> 2U));
}

[[nodiscard]] inline std::size_t hash_array16(const std::array<std::uint8_t, 16>& bytes) noexcept {
    std::size_t seed = static_cast<std::size_t>(0xcbf29ce484222325ULL);
    for (const auto byte : bytes) {
        seed ^= static_cast<std::size_t>(byte);
        seed *= static_cast<std::size_t>(0x100000001b3ULL);
    }
    return seed;
}

}  // namespace detail

struct FlowKeyV4 {
    std::uint32_t src_addr {0};
    std::uint32_t dst_addr {0};
    std::uint16_t src_port {0};
    std::uint16_t dst_port {0};
    ProtocolId protocol {ProtocolId::unknown};

    [[nodiscard]] friend constexpr bool operator==(const FlowKeyV4&, const FlowKeyV4&) = default;
    [[nodiscard]] friend constexpr auto operator<=>(const FlowKeyV4&, const FlowKeyV4&) = default;
};

struct FlowKeyV6 {
    std::array<std::uint8_t, 16> src_addr {};
    std::array<std::uint8_t, 16> dst_addr {};
    std::uint16_t src_port {0};
    std::uint16_t dst_port {0};
    ProtocolId protocol {ProtocolId::unknown};

    [[nodiscard]] friend constexpr bool operator==(const FlowKeyV6&, const FlowKeyV6&) = default;
    [[nodiscard]] friend constexpr auto operator<=>(const FlowKeyV6&, const FlowKeyV6&) = default;
};

struct FlowKeyV4Hash {
    [[nodiscard]] std::size_t operator()(const FlowKeyV4& key) const noexcept;
};

struct FlowKeyV6Hash {
    [[nodiscard]] std::size_t operator()(const FlowKeyV6& key) const noexcept;
};

}  // namespace pfl

namespace std {

template <>
struct hash<pfl::FlowKeyV4> {
    [[nodiscard]] size_t operator()(const pfl::FlowKeyV4& key) const noexcept {
        return pfl::FlowKeyV4Hash {}(key);
    }
};

template <>
struct hash<pfl::FlowKeyV6> {
    [[nodiscard]] size_t operator()(const pfl::FlowKeyV6& key) const noexcept {
        return pfl::FlowKeyV6Hash {}(key);
    }
};

}  // namespace std
