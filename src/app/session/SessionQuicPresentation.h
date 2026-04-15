#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "core/domain/Connection.h"
#include "core/domain/FlowKey.h"
#include "core/domain/PacketRef.h"
#include "core/services/TlsHandshakeDetails.h"

namespace pfl {

class CaptureSession;

namespace session_detail {

enum class QuicPresentationShellType : std::uint8_t {
    none,
    initial,
    zero_rtt,
    handshake,
    retry,
    version_negotiation,
    protected_payload,
};

enum class QuicPresentationSemanticType : std::uint8_t {
    ack,
    crypto,
    zero_rtt,
    padding,
    ping,
};

struct QuicPresentationShellMetadata {
    std::string header_form {};
    std::optional<std::uint32_t> version {};
    std::vector<std::uint8_t> dcid {};
    std::vector<std::uint8_t> scid {};
};

struct QuicPresentationResult {
    QuicPresentationShellType shell_type {QuicPresentationShellType::none};
    QuicPresentationShellMetadata shell {};
    std::vector<QuicPresentationSemanticType> semantics {};
    std::vector<QuicPresentationShellType> additional_shell_types {};
    std::vector<std::uint64_t> selected_packet_indices {};
    std::vector<std::uint64_t> crypto_packet_indices {};
    std::optional<std::string> sni {};
    std::optional<TlsHandshakeDetails> tls_handshake {};
    bool used_bounded_crypto_assembly {false};
};

struct QuicStreamPacketItem {
    std::string label {};
    std::size_t byte_count {0};
    std::string protocol_text {};
};

struct QuicStreamPacketPresentation {
    bool handled {false};
    std::vector<QuicStreamPacketItem> items {};
};

std::optional<std::vector<std::uint8_t>> find_quic_client_initial_connection_id_for_connection(
    const CaptureSession& session,
    const ConnectionV4& connection,
    std::optional<std::size_t> flow_index = std::nullopt
);

std::optional<std::vector<std::uint8_t>> find_quic_client_initial_connection_id_for_connection(
    const CaptureSession& session,
    const ConnectionV6& connection,
    std::optional<std::size_t> flow_index = std::nullopt
);

std::optional<QuicPresentationResult> build_quic_presentation_for_selected_direction(
    const CaptureSession& session,
    const FlowKeyV4& flow_key,
    std::span<const PacketRef> packets,
    const std::vector<std::uint64_t>& selected_packet_indices,
    std::span<const std::uint8_t> initial_secret_connection_id = {},
    std::optional<std::size_t> flow_index = std::nullopt
);

std::optional<QuicPresentationResult> build_quic_presentation_for_selected_direction(
    const CaptureSession& session,
    const FlowKeyV6& flow_key,
    std::span<const PacketRef> packets,
    const std::vector<std::uint64_t>& selected_packet_indices,
    std::span<const std::uint8_t> initial_secret_connection_id = {},
    std::optional<std::size_t> flow_index = std::nullopt
);

std::optional<std::string> format_quic_presentation_protocol_text(const QuicPresentationResult& result);
std::optional<std::string> format_quic_presentation_enrichment(const QuicPresentationResult& result);

QuicStreamPacketPresentation build_quic_stream_packet_presentation(
    const CaptureSession& session,
    std::size_t flow_index,
    const FlowKeyV4& flow_key,
    std::span<const PacketRef> flow_packets,
    const PacketRef& packet,
    std::span<const std::uint8_t> payload_span,
    std::span<const std::uint8_t> initial_secret_connection_id = {}
);

QuicStreamPacketPresentation build_quic_stream_packet_presentation(
    const CaptureSession& session,
    std::size_t flow_index,
    const FlowKeyV6& flow_key,
    std::span<const PacketRef> flow_packets,
    const PacketRef& packet,
    std::span<const std::uint8_t> payload_span,
    std::span<const std::uint8_t> initial_secret_connection_id = {}
);

}  // namespace session_detail
}  // namespace pfl
