#pragma once

#include <cstdint>
#include <span>
#include <string>

namespace pfl {

class HexDumpService {
public:
    [[nodiscard]] std::string format(std::span<const std::uint8_t> bytes) const;
};

}  // namespace pfl
