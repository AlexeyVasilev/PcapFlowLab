#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "app/session/FlowRows.h"
#include "core/domain/ProtocolId.h"

namespace pfl {

class CaptureSession;
class HexDumpService;

namespace session_detail {

enum class StreamItemDataSourceKind : std::uint8_t {
    captured_packet_range = 0,
    retained_item_bytes,
    reconstructed_item,
    unavailable,
};

enum class StreamItemDataState : std::uint8_t {
    complete = 0,
    partial,
    truncated,
    window_incomplete,
    synthetic,
    unavailable,
};

enum class StreamItemDataSemanticKind : std::uint8_t {
    tcp_payload = 0,
    http_message,
    tls_record,
    tls_handshake,
    quic_packet,
    quic_frame,
    quic_crypto_data,
    opaque_payload,
    other,
};

enum class StreamItemDataAssemblyKind : std::uint8_t {
    packet_local = 0,
    reassembled,
};

enum class StreamItemDataContributionUnitKind : std::uint8_t {
    tcp_segment = 0,
    quic_crypto_frame,
};

struct StreamItemCapturedPacketRange {
    std::uint64_t packet_index {0};
    std::uint32_t offset {0};
    std::uint32_t available_length {0};
    std::optional<std::uint32_t> declared_length {};
};

struct SelectedStreamItemDataPresentation {
    std::uint64_t stream_item_index {0};
    StreamItemDataSemanticKind semantic_kind {StreamItemDataSemanticKind::other};
    StreamItemDataSourceKind source_kind {StreamItemDataSourceKind::unavailable};
    StreamItemDataState state {StreamItemDataState::unavailable};
    StreamItemDataAssemblyKind assembly_kind {StreamItemDataAssemblyKind::packet_local};
    std::uint32_t available_length {0};
    std::optional<std::uint32_t> declared_length {};
    std::optional<StreamItemCapturedPacketRange> captured_packet_range {};
    std::optional<std::uint32_t> contributing_unit_count {};
    std::optional<StreamItemDataContributionUnitKind> contributing_unit_kind {};
    std::optional<std::uint64_t> quic_crypto_stream_offset {};
    std::vector<std::uint8_t> owned_bytes {};
    std::string unavailable_reason {};
};

[[nodiscard]] std::string to_string(StreamItemDataSourceKind source_kind);
[[nodiscard]] std::string to_string(StreamItemDataState state);
[[nodiscard]] std::string to_string(StreamItemDataSemanticKind semantic_kind);
[[nodiscard]] std::string to_string(StreamItemDataAssemblyKind assembly_kind);
[[nodiscard]] std::string to_string(StreamItemDataContributionUnitKind contribution_unit_kind);

[[nodiscard]] std::string format_selected_stream_item_data_status_text(
    const SelectedStreamItemDataPresentation& presentation
);

[[nodiscard]] SelectedStreamItemDataPresentation derive_selected_stream_item_data_presentation(
    const CaptureSession& session,
    std::size_t flow_index,
    ProtocolId flow_protocol,
    const StreamItemRow& row,
    StreamMaterializationStability stability,
    std::uint32_t intra_packet_ordinal
);

[[nodiscard]] std::optional<std::vector<std::uint8_t>> materialize_selected_stream_item_data(
    const SelectedStreamItemDataPresentation& presentation,
    std::span<const std::uint8_t> captured_packet_bytes
);

[[nodiscard]] std::optional<std::string> format_selected_stream_item_data_hex_dump(
    const SelectedStreamItemDataPresentation& presentation,
    std::span<const std::uint8_t> captured_packet_bytes,
    const HexDumpService& hex_dump_service
);

}  // namespace session_detail
}  // namespace pfl
