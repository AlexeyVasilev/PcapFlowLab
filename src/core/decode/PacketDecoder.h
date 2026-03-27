#pragma once

#include <optional>

#include "core/domain/IngestedPacket.h"
#include "core/io/PcapReader.h"

namespace pfl {

struct DecodedPacket {
    std::optional<IngestedPacketV4> ipv4 {};
    std::optional<IngestedPacketV6> ipv6 {};

    [[nodiscard]] bool has_value() const noexcept {
        return ipv4.has_value() || ipv6.has_value();
    }
};

class PacketDecoder {
public:
    [[nodiscard]] DecodedPacket decode(const RawPcapPacket& packet) const noexcept;
    [[nodiscard]] DecodedPacket decode_ethernet(const RawPcapPacket& packet) const noexcept;
};

}  // namespace pfl
