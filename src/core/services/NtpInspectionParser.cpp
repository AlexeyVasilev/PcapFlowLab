#include "core/services/NtpInspectionParser.h"

#include <cstdint>

namespace pfl {

namespace {

constexpr std::uint16_t kNtpPort = 123U;

std::uint32_t read_be32(const std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 3U]);
}

std::int8_t read_i8(const std::uint8_t value) noexcept {
    const auto signed_value = value <= 0x7FU
        ? static_cast<int>(value)
        : static_cast<int>(value) - 0x100;
    return static_cast<std::int8_t>(signed_value);
}

NtpTimestamp read_timestamp(const std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    return NtpTimestamp {
        .seconds = read_be32(bytes, offset),
        .fraction = read_be32(bytes, offset + 4U),
    };
}

}  // namespace

std::optional<NtpMessage> NtpInspectionParser::inspect(const std::span<const std::uint8_t> ntp_bytes) const noexcept {
    if (ntp_bytes.size() != kBasicHeaderSize) {
        return std::nullopt;
    }

    return NtpMessage {
        .leap_indicator = static_cast<std::uint8_t>((ntp_bytes[0] >> 6U) & 0x03U),
        .version = static_cast<std::uint8_t>((ntp_bytes[0] >> 3U) & 0x07U),
        .mode = static_cast<std::uint8_t>(ntp_bytes[0] & 0x07U),
        .stratum = ntp_bytes[1],
        .poll = read_i8(ntp_bytes[2]),
        .precision = read_i8(ntp_bytes[3]),
        .root_delay_raw = read_be32(ntp_bytes, 4U),
        .root_dispersion_raw = read_be32(ntp_bytes, 8U),
        .reference_id = {ntp_bytes[12], ntp_bytes[13], ntp_bytes[14], ntp_bytes[15]},
        .reference_timestamp = read_timestamp(ntp_bytes, 16U),
        .originate_timestamp = read_timestamp(ntp_bytes, 24U),
        .receive_timestamp = read_timestamp(ntp_bytes, 32U),
        .transmit_timestamp = read_timestamp(ntp_bytes, 40U),
    };
}

bool ntp_message_matches_current_support_contract(
    const NtpMessage& message,
    const NtpRecognitionContext& context
) noexcept {
    if (!context.declared_udp_payload_length.has_value() ||
        *context.declared_udp_payload_length != NtpInspectionParser::kBasicHeaderSize) {
        return false;
    }

    if (message.version != 3U && message.version != 4U) {
        return false;
    }

    if (message.mode == 3U) {
        if (context.dst_port != kNtpPort) {
            return false;
        }
    } else if (message.mode == 4U) {
        if (context.src_port != kNtpPort) {
            return false;
        }
    } else {
        return false;
    }

    return message.stratum <= 16U;
}

std::optional<NtpMessage> inspect_supported_ntp_message(
    const std::span<const std::uint8_t> ntp_bytes,
    const NtpRecognitionContext& context
) noexcept {
    NtpInspectionParser parser {};
    auto message = parser.inspect(ntp_bytes);
    if (!message.has_value() ||
        !ntp_message_matches_current_support_contract(*message, context)) {
        return std::nullopt;
    }
    return message;
}

}  // namespace pfl
