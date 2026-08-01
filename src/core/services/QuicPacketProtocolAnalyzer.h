#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace pfl {

enum class QuicPacketHeaderForm : std::uint8_t {
    short_header,
    long_header,
};

enum class QuicPacketType : std::uint8_t {
    initial,
    zero_rtt,
    handshake,
    retry,
    version_negotiation,
    protected_payload,
};

struct QuicFramePresenceSummary {
    bool ack {false};
    bool crypto {false};
    bool padding {false};
    bool stream {false};
};

struct QuicInspectedPacket {
    QuicPacketHeaderForm header_form {QuicPacketHeaderForm::short_header};
    QuicPacketType packet_type {QuicPacketType::protected_payload};
    std::optional<std::uint32_t> version {};
    std::vector<std::uint8_t> dcid {};
    std::vector<std::uint8_t> scid {};
    std::vector<std::uint32_t> supported_versions {};
    std::optional<QuicFramePresenceSummary> frame_summary {};
    std::optional<std::string> sni {};
    std::vector<std::uint8_t> tls_crypto_prefix {};
    std::size_t packet_bytes_consumed {0U};
};

struct QuicDatagramInspection {
    std::vector<QuicInspectedPacket> packets {};
};

class QuicPacketProtocolAnalyzer {
public:
    [[nodiscard]] std::optional<std::string> analyze(std::span<const std::uint8_t> packet_bytes) const;
    [[nodiscard]] std::optional<std::string> analyze(std::span<const std::uint8_t> packet_bytes, std::uint32_t data_link_type) const;
    [[nodiscard]] std::optional<std::string> analyze_udp_payload(std::span<const std::uint8_t> udp_payload) const;
    [[nodiscard]] std::optional<QuicDatagramInspection> inspect(std::span<const std::uint8_t> packet_bytes) const;
    [[nodiscard]] std::optional<QuicDatagramInspection> inspect(
        std::span<const std::uint8_t> packet_bytes,
        std::uint32_t data_link_type
    ) const;
    [[nodiscard]] std::optional<QuicDatagramInspection> inspect_udp_payload(std::span<const std::uint8_t> udp_payload) const;
};

}  // namespace pfl
