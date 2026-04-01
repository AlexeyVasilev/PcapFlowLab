#pragma once

#include <cstdint>
#include <span>
#include <unordered_map>
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
    struct QuicInitialFlowState {
        std::vector<std::vector<std::uint8_t>> initial_payloads {};
        bool exhausted {false};
    };

    AnalysisSettings settings_ {};
    bool enable_quic_initial_sni_ {false};
    mutable std::unordered_map<FlowKeyV4, QuicInitialFlowState> quic_initial_ipv4_states_ {};
    mutable std::unordered_map<FlowKeyV6, QuicInitialFlowState> quic_initial_ipv6_states_ {};
};

}  // namespace pfl

