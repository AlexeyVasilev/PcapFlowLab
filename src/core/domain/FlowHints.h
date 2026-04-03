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
    ssh = 5,
    stun = 6,
    bittorrent = 7,
    dhcp = 8,
    mdns = 9,
    smtp = 10,
    pop3 = 11,
    imap = 12,
};

enum class QuicVersionHint : std::uint8_t {
    unknown = 0,
    v1 = 1,
    draft29 = 2,
    v2 = 3,
};

enum class TlsVersionHint : std::uint8_t {
    unknown = 0,
    tls12 = 1,
    tls13 = 2,
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

[[nodiscard]] constexpr TlsVersionHint classify_tls_version(const std::uint16_t version) noexcept {
    switch (version) {
    case 0x0303U:
        return TlsVersionHint::tls12;
    case 0x0304U:
        return TlsVersionHint::tls13;
    default:
        return TlsVersionHint::unknown;
    }
}

struct FlowHintUpdate {
    FlowProtocolHint protocol_hint {FlowProtocolHint::unknown};
    std::string service_hint {};
    QuicVersionHint quic_version {QuicVersionHint::unknown};
    TlsVersionHint tls_version {TlsVersionHint::unknown};
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
    case FlowProtocolHint::ssh:
        return "ssh";
    case FlowProtocolHint::stun:
        return "stun";
    case FlowProtocolHint::bittorrent:
        return "bittorrent";
    case FlowProtocolHint::dhcp:
        return "dhcp";
    case FlowProtocolHint::mdns:
        return "mdns";
    case FlowProtocolHint::smtp:
        return "smtp";
    case FlowProtocolHint::pop3:
        return "pop3";
    case FlowProtocolHint::imap:
        return "imap";
    default:
        return "unknown";
    }
}

}  // namespace pfl

