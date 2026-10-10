#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "core/domain/DhcpInspection.h"

namespace pfl {

struct DhcpRecognitionContext {
    std::uint16_t src_port {0U};
    std::uint16_t dst_port {0U};
};

class DhcpInspectionParser {
public:
    static constexpr std::size_t kBootpFixedHeaderSize = 236U;
    static constexpr std::size_t kMagicCookieOffset = kBootpFixedHeaderSize;
    static constexpr std::size_t kMinPayloadSize = kMagicCookieOffset + 4U;
    static constexpr std::size_t kOptionsOffset = kMinPayloadSize;
    static constexpr std::uint32_t kMagicCookie = 0x63825363U;

    [[nodiscard]] std::optional<DhcpMessage> inspect(std::span<const std::uint8_t> dhcp_bytes) const;
};

[[nodiscard]] bool dhcp_message_matches_current_support_contract(
    std::span<const std::uint8_t> dhcp_bytes,
    DhcpRecognitionContext context
) noexcept;

[[nodiscard]] std::optional<DhcpMessage> inspect_supported_dhcp_message(
    std::span<const std::uint8_t> dhcp_bytes,
    DhcpRecognitionContext context
);

}  // namespace pfl
