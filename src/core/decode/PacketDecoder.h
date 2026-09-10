#pragma once

#include "core/domain/DecodedPacket.h"
#include "core/io/PcapReader.h"

namespace pfl {

class PacketDecoder {
public:
    [[nodiscard]] DecodedPacket decode(const RawPcapPacket& packet) const noexcept;
    [[nodiscard]] DecodedPacket decode_ethernet(const RawPcapPacket& packet) const noexcept;
};

}  // namespace pfl
