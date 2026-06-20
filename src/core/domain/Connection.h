#pragma once

#include <cstdint>
#include <string>

#include "core/domain/ConnectionKey.h"
#include "core/domain/Flow.h"
#include "core/domain/FlowHints.h"

namespace pfl {

inline constexpr std::uint8_t kMaxUnresolvedHintPayloadAttemptsPerConnection = 10U;

struct ConnectionHintSearchState {
    std::uint8_t unresolved_payload_attempt_count {0};
    bool unresolved_payload_attempt_budget_exhausted {false};
};

struct ConnectionV4 {
    ConnectionKeyV4 key {};

    FlowV4 flow_a {};
    FlowV4 flow_b {};

    bool has_flow_a {false};
    bool has_flow_b {false};

    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};
    bool has_fragmented_packets {false};
    std::uint64_t fragmented_packet_count {0};
    FlowProtocolHint protocol_hint {FlowProtocolHint::unknown};
    std::string service_hint {};
    QuicVersionHint quic_version {QuicVersionHint::unknown};
    TlsVersionHint tls_version {TlsVersionHint::unknown};
    ConnectionHintSearchState hint_search_state {};

    void add_packet(const FlowKeyV4& packet_key, const PacketRef& packet);
    void apply_hints(const FlowHintUpdate& hints);
    [[nodiscard]] bool hint_detection_settled() const noexcept;
    [[nodiscard]] bool should_attempt_hint_detection(const PacketRef& packet, ProtocolId protocol) const noexcept;
    void note_hint_detection_attempt(const PacketRef& packet, ProtocolId protocol) noexcept;
};

struct ConnectionV6 {
    ConnectionKeyV6 key {};

    FlowV6 flow_a {};
    FlowV6 flow_b {};

    bool has_flow_a {false};
    bool has_flow_b {false};

    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};
    bool has_fragmented_packets {false};
    std::uint64_t fragmented_packet_count {0};
    FlowProtocolHint protocol_hint {FlowProtocolHint::unknown};
    std::string service_hint {};
    QuicVersionHint quic_version {QuicVersionHint::unknown};
    TlsVersionHint tls_version {TlsVersionHint::unknown};
    ConnectionHintSearchState hint_search_state {};

    void add_packet(const FlowKeyV6& packet_key, const PacketRef& packet);
    void apply_hints(const FlowHintUpdate& hints);
    [[nodiscard]] bool hint_detection_settled() const noexcept;
    [[nodiscard]] bool should_attempt_hint_detection(const PacketRef& packet, ProtocolId protocol) const noexcept;
    void note_hint_detection_attempt(const PacketRef& packet, ProtocolId protocol) noexcept;
};

}  // namespace pfl

