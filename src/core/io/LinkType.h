#pragma once

#include <cstdint>

namespace pfl {

inline constexpr std::uint32_t kLinkTypeEthernet = 1U;
inline constexpr std::uint32_t kLinkTypeLinuxSll = 113U;
inline constexpr std::uint32_t kLinkTypeLinuxSll2 = 276U;

[[nodiscard]] constexpr bool is_linux_cooked_link_type(const std::uint32_t link_type) noexcept {
    return link_type == kLinkTypeLinuxSll || link_type == kLinkTypeLinuxSll2;
}

[[nodiscard]] constexpr bool is_supported_capture_link_type(const std::uint32_t link_type) noexcept {
    return link_type == kLinkTypeEthernet || is_linux_cooked_link_type(link_type);
}

}  // namespace pfl
