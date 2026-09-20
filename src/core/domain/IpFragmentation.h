#pragma once

#include <cstdint>

namespace pfl {

enum class IpFragmentationKind : std::uint8_t {
    none = 0,
    ipv4_initial,
    ipv4_non_initial,
    ipv6_initial,
    ipv6_non_initial,
    ipv6_atomic,
};

[[nodiscard]] constexpr bool is_real_ip_fragment(const IpFragmentationKind kind) noexcept {
    return kind == IpFragmentationKind::ipv4_initial ||
           kind == IpFragmentationKind::ipv4_non_initial ||
           kind == IpFragmentationKind::ipv6_initial ||
           kind == IpFragmentationKind::ipv6_non_initial;
}

[[nodiscard]] constexpr bool is_ipv6_atomic_fragment(const IpFragmentationKind kind) noexcept {
    return kind == IpFragmentationKind::ipv6_atomic;
}

}  // namespace pfl
