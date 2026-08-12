#pragma once

#include <cstdint>
#include <string_view>

namespace pfl {

inline constexpr std::uint32_t kLinkTypeEthernet = 1U;
inline constexpr std::uint32_t kLinkTypeLinuxSll = 113U;
inline constexpr std::uint32_t kLinkTypeLinuxSll2 = 276U;

[[nodiscard]] constexpr std::string_view capture_link_type_name(const std::uint32_t link_type) noexcept {
    switch (link_type) {
    case kLinkTypeEthernet:
        return "Ethernet";
    case kLinkTypeLinuxSll:
        return "Linux cooked capture v1";
    case kLinkTypeLinuxSll2:
        return "Linux cooked capture v2";
    default:
        return {};
    }
}

[[nodiscard]] constexpr bool is_linux_cooked_link_type(const std::uint32_t link_type) noexcept {
    return link_type == kLinkTypeLinuxSll || link_type == kLinkTypeLinuxSll2;
}

[[nodiscard]] constexpr bool is_supported_capture_link_type(const std::uint32_t link_type) noexcept {
    return link_type == kLinkTypeEthernet || is_linux_cooked_link_type(link_type);
}

}  // namespace pfl
