#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace pfl {

class PacketPayloadService {
public:
    [[nodiscard]] std::vector<std::uint8_t> extract_transport_payload(std::span<const std::uint8_t> packet_bytes) const;
};

}  // namespace pfl
