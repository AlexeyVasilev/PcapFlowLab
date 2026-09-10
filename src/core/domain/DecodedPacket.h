#pragma once

#include <optional>

#include "core/domain/IngestedPacket.h"
#include "core/domain/ProtocolPath.h"
#include "core/domain/TerminalTransportPayloadBounds.h"

namespace pfl {

struct DecodedPacket {
    std::optional<IngestedPacketV4> ipv4 {};
    std::optional<IngestedPacketV6> ipv6 {};
    ProtocolPathBuilder protocol_path_builder {};
    std::optional<TerminalTransportPayloadBounds> terminal_transport_payload_bounds {};

    [[nodiscard]] bool has_value() const noexcept {
        return ipv4.has_value() || ipv6.has_value();
    }
};

}  // namespace pfl
