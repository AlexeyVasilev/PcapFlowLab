#pragma once

#include <optional>
#include <cstdint>
#include <span>
#include <unordered_map>
#include <vector>

#include "core/domain/FlowHints.h"
#include "core/domain/FlowKey.h"
#include "core/domain/TerminalTransportPayloadBounds.h"
#include "core/services/AnalysisSettings.h"

namespace pfl {

struct CaptureState;
struct PacketDetails;
class PacketPayloadService;

struct PendingTlsClientHello {
    std::vector<std::uint8_t> retained_prefix {};
    std::uint32_t expected_next_sequence_number {0U};
    std::size_t expected_client_hello_end {0U};
};

class FlowHintService {
public:
    explicit FlowHintService(AnalysisSettings settings = {}, bool enable_quic_initial_sni = false);
    [[nodiscard]] const AnalysisSettings& settings() const noexcept;

    [[nodiscard]] FlowHintUpdate detect(std::span<const std::uint8_t> packet_bytes, const FlowKeyV4& flow_key) const;
    [[nodiscard]] FlowHintUpdate detect(std::span<const std::uint8_t> packet_bytes,
                                        std::uint32_t data_link_type,
                                        const FlowKeyV4& flow_key) const;
    [[nodiscard]] FlowHintUpdate detect(std::span<const std::uint8_t> packet_bytes,
                                        std::uint32_t data_link_type,
                                        const FlowKeyV4& flow_key,
                                        std::optional<TerminalTransportPayloadBounds> terminal_transport_payload_bounds) const;
    [[nodiscard]] FlowHintUpdate detect(std::span<const std::uint8_t> packet_bytes, const FlowKeyV6& flow_key) const;
    [[nodiscard]] FlowHintUpdate detect(std::span<const std::uint8_t> packet_bytes,
                                        std::uint32_t data_link_type,
                                        const FlowKeyV6& flow_key) const;
    [[nodiscard]] FlowHintUpdate detect(std::span<const std::uint8_t> packet_bytes,
                                        std::uint32_t data_link_type,
                                        const FlowKeyV6& flow_key,
                                        std::optional<TerminalTransportPayloadBounds> terminal_transport_payload_bounds) const;
    [[nodiscard]] bool retain_tls_client_hello_prefix(std::span<const std::uint8_t> packet_bytes,
                                                      std::uint32_t data_link_type,
                                                      const FlowKeyV4& flow_key,
                                                      TerminalTransportPayloadBounds terminal_transport_payload_bounds,
                                                      std::uint32_t tcp_sequence_number,
                                                      std::uint8_t tcp_flags) const;
    [[nodiscard]] bool retain_tls_client_hello_prefix(std::span<const std::uint8_t> packet_bytes,
                                                      std::uint32_t data_link_type,
                                                      const FlowKeyV6& flow_key,
                                                      TerminalTransportPayloadBounds terminal_transport_payload_bounds,
                                                      std::uint32_t tcp_sequence_number,
                                                      std::uint8_t tcp_flags) const;
    [[nodiscard]] FlowHintUpdate attempt_tls_client_hello_continuation(std::span<const std::uint8_t> packet_bytes,
                                                                       std::uint32_t data_link_type,
                                                                       const FlowKeyV4& flow_key,
                                                                       TerminalTransportPayloadBounds terminal_transport_payload_bounds,
                                                                       std::uint32_t tcp_sequence_number) const;
    [[nodiscard]] FlowHintUpdate attempt_tls_client_hello_continuation(std::span<const std::uint8_t> packet_bytes,
                                                                       std::uint32_t data_link_type,
                                                                       const FlowKeyV6& flow_key,
                                                                       TerminalTransportPayloadBounds terminal_transport_payload_bounds,
                                                                       std::uint32_t tcp_sequence_number) const;
    void discard_pending_tls_client_hello(const FlowKeyV4& flow_key) const;
    void discard_pending_tls_client_hello(const FlowKeyV6& flow_key) const;
    [[nodiscard]] bool has_pending_tls_client_hello(const FlowKeyV4& flow_key) const;
    [[nodiscard]] bool has_pending_tls_client_hello(const FlowKeyV6& flow_key) const;
    [[nodiscard]] std::size_t pending_tls_client_hello_candidate_count() const noexcept;
    [[nodiscard]] std::size_t pending_tls_client_hello_retained_bytes() const noexcept;
    void clear_pending_tls_client_hello_candidates(CaptureState& state) const;

private:
    struct QuicInitialFlowState {
        std::vector<std::vector<std::uint8_t>> initial_payloads {};
        bool exhausted {false};
    };

    AnalysisSettings settings_ {};
    bool enable_quic_initial_sni_ {false};
    mutable std::unordered_map<FlowKeyV4, QuicInitialFlowState> quic_initial_ipv4_states_ {};
    mutable std::unordered_map<FlowKeyV6, QuicInitialFlowState> quic_initial_ipv6_states_ {};
    mutable std::unordered_map<FlowKeyV4, PendingTlsClientHello> pending_tls_client_hello_ipv4_ {};
    mutable std::unordered_map<FlowKeyV6, PendingTlsClientHello> pending_tls_client_hello_ipv6_ {};
    mutable std::size_t pending_tls_client_hello_retained_bytes_ {0U};
};

[[nodiscard]] bool packet_matches_mdns_hint(const PacketDetails& details) noexcept;

}  // namespace pfl

