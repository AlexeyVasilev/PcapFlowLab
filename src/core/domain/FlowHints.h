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

enum class QuicVersionHint : std::uint8_t {
    unknown = 0,
    v1 = 1,
    draft29 = 2,
    v2 = 3,
};

[[nodiscard]] constexpr QuicVersionHint classify_quic_version(const std::uint32_t version) noexcept {
    switch (version) {
    case 0x00000001U:
        return QuicVersionHint::v1;
    case 0xFF00001DU:
        return QuicVersionHint::draft29;
    case 0x6B3343CFU:
        return QuicVersionHint::v2;
    default:
        return QuicVersionHint::unknown;
    }
}

struct FlowHintUpdate {
    FlowProtocolHint protocol_hint {FlowProtocolHint::unknown};
    std::string service_hint {};
    QuicVersionHint quic_version {QuicVersionHint::unknown};
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

