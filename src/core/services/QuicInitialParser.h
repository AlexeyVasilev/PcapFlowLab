#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace pfl {

class QuicInitialParser {
public:
    [[nodiscard]] std::optional<std::string> extract_client_initial_sni(std::span<const std::uint8_t> udp_payload) const;
};

}  // namespace pfl
