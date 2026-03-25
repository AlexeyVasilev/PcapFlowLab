#pragma once

#include <span>
#include <vector>

#include "core/domain/FlowHints.h"
#include "core/domain/FlowKey.h"

namespace pfl {

class PacketPayloadService;

class FlowHintService {
public:
    [[nodiscard]] FlowHintUpdate detect(std::span<const std::uint8_t> packet_bytes, const FlowKeyV4& flow_key) const;
    [[nodiscard]] FlowHintUpdate detect(std::span<const std::uint8_t> packet_bytes, const FlowKeyV6& flow_key) const;
};

}  // namespace pfl
