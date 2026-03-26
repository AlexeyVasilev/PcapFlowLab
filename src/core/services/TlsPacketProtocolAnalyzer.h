#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace pfl {

class TlsPacketProtocolAnalyzer {
public:
    [[nodiscard]] std::optional<std::string> analyze(std::span<const std::uint8_t> packet_bytes) const;
};

}  // namespace pfl
