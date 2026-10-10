#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "core/domain/NtpInspection.h"

namespace pfl {

struct NtpRecognitionContext {
    std::uint16_t src_port {0U};
    std::uint16_t dst_port {0U};
    std::optional<std::size_t> declared_udp_payload_length {};
};

class NtpInspectionParser {
public:
    static constexpr std::size_t kBasicHeaderSize = 48U;

    [[nodiscard]] std::optional<NtpMessage> inspect(std::span<const std::uint8_t> ntp_bytes) const noexcept;
};

[[nodiscard]] bool ntp_message_matches_current_support_contract(
    const NtpMessage& message,
    const NtpRecognitionContext& context
) noexcept;

[[nodiscard]] std::optional<NtpMessage> inspect_supported_ntp_message(
    std::span<const std::uint8_t> ntp_bytes,
    const NtpRecognitionContext& context
) noexcept;

}  // namespace pfl
