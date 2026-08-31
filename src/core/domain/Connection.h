#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "core/domain/ConnectionKey.h"
#include "core/domain/Flow.h"
#include "core/domain/FlowHints.h"
#include "core/domain/IngestedPacket.h"

namespace pfl {

inline constexpr std::uint8_t kMaxUnresolvedHintPayloadAttemptsPerConnection = 10U;

struct ConnectionHintSearchState {
    std::uint8_t unresolved_payload_attempt_count {0};
    bool unresolved_payload_attempt_budget_exhausted {false};
};

struct ConnectionAggregateStats {
    std::uint64_t first_timestamp_us {0};
    std::uint64_t last_timestamp_us {0};
    std::uint64_t captured_bytes {0};
    std::uint64_t truncated_packet_count {0};
    std::uint64_t tcp_syn_count {0};
    std::uint64_t tcp_fin_count {0};
    std::uint64_t tcp_rst_count {0};
    std::uint32_t max_original_packet_length {0};
    std::uint32_t max_captured_packet_length {0};

    [[nodiscard]] friend constexpr bool operator==(
        const ConnectionAggregateStats&,
        const ConnectionAggregateStats&
    ) = default;
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
    ConnectionAggregateStats aggregate_stats {};
    ConnectionHintSearchState hint_search_state {};

    void add_packet(const FlowKeyV4& packet_key, const PacketRef& packet, const PacketImportMetadata& metadata = {});
    void apply_hints(const FlowHintUpdate& hints);
    [[nodiscard]] bool hint_detection_settled() const noexcept;
    [[nodiscard]] bool should_attempt_hint_detection(const PacketImportMetadata& metadata, ProtocolId protocol) const noexcept;
    void note_hint_detection_attempt(const PacketImportMetadata& metadata, ProtocolId protocol) noexcept;
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
    ConnectionAggregateStats aggregate_stats {};
    ConnectionHintSearchState hint_search_state {};

    void add_packet(const FlowKeyV6& packet_key, const PacketRef& packet, const PacketImportMetadata& metadata = {});
    void apply_hints(const FlowHintUpdate& hints);
    [[nodiscard]] bool hint_detection_settled() const noexcept;
    [[nodiscard]] bool should_attempt_hint_detection(const PacketImportMetadata& metadata, ProtocolId protocol) const noexcept;
    void note_hint_detection_attempt(const PacketImportMetadata& metadata, ProtocolId protocol) noexcept;
};

[[nodiscard]] std::optional<FlowKeyV4> first_observed_flow_key(const ConnectionV4& connection) noexcept;
[[nodiscard]] std::optional<FlowKeyV6> first_observed_flow_key(const ConnectionV6& connection) noexcept;
[[nodiscard]] std::optional<EndpointKeyV4> first_observed_endpoint_a(const ConnectionV4& connection) noexcept;
[[nodiscard]] std::optional<EndpointKeyV4> first_observed_endpoint_b(const ConnectionV4& connection) noexcept;
[[nodiscard]] std::optional<EndpointKeyV6> first_observed_endpoint_a(const ConnectionV6& connection) noexcept;
[[nodiscard]] std::optional<EndpointKeyV6> first_observed_endpoint_b(const ConnectionV6& connection) noexcept;
[[nodiscard]] bool has_valid_first_observed_orientation(const ConnectionV4& connection) noexcept;
[[nodiscard]] bool has_valid_first_observed_orientation(const ConnectionV6& connection) noexcept;

}  // namespace pfl

