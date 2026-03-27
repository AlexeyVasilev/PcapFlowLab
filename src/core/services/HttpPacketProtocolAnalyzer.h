#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace pfl {

class HttpPacketProtocolAnalyzer {
public:
    [[nodiscard]] std::optional<std::string> analyze(std::span<const std::uint8_t> packet_bytes) const;
    [[nodiscard]] std::optional<std::string> analyze(std::span<const std::uint8_t> packet_bytes, std::uint32_t data_link_type) const;
};

}  // namespace pfl

