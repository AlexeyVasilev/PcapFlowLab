#pragma once

#include <cstdint>
#include <span>

namespace pfl {

class IByteSource {
public:
    virtual ~IByteSource() = default;
    virtual bool read_at(std::uint64_t offset, std::span<std::uint8_t> buffer) = 0;
};

}  // namespace pfl
