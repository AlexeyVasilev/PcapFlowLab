#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "core/domain/StunInspection.h"

namespace pfl {

struct StunEnvelope {
    std::uint16_t message_type {0U};
    std::uint16_t message_length {0U};
    std::uint32_t magic_cookie {0U};
    std::array<std::uint8_t, 12> transaction_id {};
};

class StunInspectionParser {
public:
    static constexpr std::size_t kHeaderSize = 20U;
    static constexpr std::uint32_t kMagicCookie = 0x2112A442U;

    [[nodiscard]] std::optional<StunMessage> inspect(std::span<const std::uint8_t> stun_bytes) const;
};

[[nodiscard]] std::optional<StunEnvelope> inspect_stun_envelope(
    std::span<const std::uint8_t> stun_bytes
) noexcept;

[[nodiscard]] bool stun_message_matches_current_support_contract(
    std::span<const std::uint8_t> stun_bytes
) noexcept;

[[nodiscard]] std::optional<StunMessage> inspect_supported_stun_message(
    std::span<const std::uint8_t> stun_bytes
);

}  // namespace pfl
