#pragma once

#include <vector>

#include "core/domain/PacketRef.h"
#include "core/io/IByteSource.h"

namespace pfl {

class PacketDataReader {
public:
    explicit PacketDataReader(IByteSource& source) noexcept;

    [[nodiscard]] std::vector<std::uint8_t> read_packet_data(const PacketRef& packet) const;
    [[nodiscard]] bool read_packet_data(const PacketRef& packet, std::vector<std::uint8_t>& out) const;

private:
    IByteSource& source_;
};

}  // namespace pfl
