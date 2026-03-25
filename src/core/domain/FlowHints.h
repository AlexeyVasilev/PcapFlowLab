#pragma once

#include <cstdint>
#include <string>

namespace pfl {

enum class FlowProtocolHint : std::uint8_t {
    unknown = 0,
    tls = 1,
    http = 2,
    dns = 3,
    quic = 4,
};

struct FlowHintUpdate {
    FlowProtocolHint protocol_hint {FlowProtocolHint::unknown};
    std::string service_hint {};
};

[[nodiscard]] constexpr const char* flow_protocol_hint_text(const FlowProtocolHint hint) noexcept {
    switch (hint) {
    case FlowProtocolHint::tls:
        return "tls";
    case FlowProtocolHint::http:
        return "http";
    case FlowProtocolHint::dns:
        return "dns";
    case FlowProtocolHint::quic:
        return "quic";
    default:
        return "unknown";
    }
}

}  // namespace pfl
