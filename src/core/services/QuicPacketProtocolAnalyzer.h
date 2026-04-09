#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace pfl {

class QuicPacketProtocolAnalyzer {
public:
    [[nodiscard]] std::optional<std::string> analyze(std::span<const std::uint8_t> packet_bytes) const;
    [[nodiscard]] std::optional<std::string> analyze(std::span<const std::uint8_t> packet_bytes, std::uint32_t data_link_type) const;
    [[nodiscard]] std::optional<std::string> analyze_udp_payload(std::span<const std::uint8_t> udp_payload) const;
};

}  // namespace pfl