#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "core/domain/FlowHints.h"
#include "core/domain/FlowKey.h"
#include "core/services/AnalysisSettings.h"

namespace pfl {

class PacketPayloadService;

class FlowHintService {
public:
    explicit FlowHintService(AnalysisSettings settings = {}, bool enable_quic_initial_sni = false);

    [[nodiscard]] FlowHintUpdate detect(std::span<const std::uint8_t> packet_bytes, const FlowKeyV4& flow_key) const;
    [[nodiscard]] FlowHintUpdate detect(std::span<const std::uint8_t> packet_bytes,
                                        std::uint32_t data_link_type,
                                        const FlowKeyV4& flow_key) const;
    [[nodiscard]] FlowHintUpdate detect(std::span<const std::uint8_t> packet_bytes, const FlowKeyV6& flow_key) const;
    [[nodiscard]] FlowHintUpdate detect(std::span<const std::uint8_t> packet_bytes,
                                        std::uint32_t data_link_type,
                                        const FlowKeyV6& flow_key) const;

private:
    AnalysisSettings settings_ {};
    bool enable_quic_initial_sni_ {false};
};

}  // namespace pfl
