#pragma once

#include <optional>
#include <span>

#include "core/domain/PacketDetails.h"
#include "core/domain/PacketRef.h"

namespace pfl {

class PacketDetailsService {
public:
    [[nodiscard]] std::optional<PacketDetails> decode(
        std::span<const std::uint8_t> packet_bytes,
        const PacketRef& packet_ref
    ) const;
};

}  // namespace pfl
