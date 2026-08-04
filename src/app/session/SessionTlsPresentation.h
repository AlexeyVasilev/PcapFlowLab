#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "app/session/FlowRows.h"
#include "core/domain/Direction.h"
#include "core/domain/PacketRef.h"
#include "core/services/TlsInspectionModel.h"

namespace pfl {

class CaptureSession;

namespace session_detail {

struct TlsStreamPresentationItem {
    std::string label {};
    std::size_t byte_count {0U};
    std::vector<std::uint64_t> packet_indices {};
    StreamMaterializationStability stability {StreamMaterializationStability::stable};
    bool has_constricted_contribution {false};
    std::vector<std::string> constricted_contribution_notes {};
    std::vector<std::string> constricted_packet_notes {};
    std::vector<std::uint8_t> summary_payload_bytes {};
    std::vector<TlsRecordModel> summary_records {};
    std::string payload_hex_text {};
    TlsStreamItemSemanticKind semantic_kind {TlsStreamItemSemanticKind::none};
    TlsInspectionParserContext initial_parser_context {};
    TlsInspectionParserContext final_parser_context {};
};

struct TlsStreamScannerContribution {
    std::uint64_t packet_index {0};
    std::uint64_t flow_packet_index {0};
    std::vector<std::uint8_t> captured_bytes {};
    std::size_t original_byte_count {0U};
    std::uint32_t packet_captured_length {0U};
    std::uint32_t packet_original_length {0U};
};

struct TlsScannedStreamRow {
    TlsStreamPresentationItem item {};
    std::uint64_t first_packet_index {0};
    std::uint64_t first_flow_packet_index {0};
    std::uint32_t intra_packet_ordinal {0U};
};

enum class TlsStreamScannerFinishMode : std::uint8_t {
    none = 0,
    window_end,
    flow_end,
    tcp_gap,
};

struct TlsStreamScannerPendingRecordState {
    std::string label {};
    std::size_t total_byte_count {0U};
    TlsStreamItemSemanticKind semantic_kind {TlsStreamItemSemanticKind::none};
    TlsInspectionParserContext initial_parser_context {};
    std::uint64_t first_packet_index {0};
    std::uint64_t first_flow_packet_index {0};
    std::uint32_t intra_packet_ordinal {0U};
};

struct TlsStreamScannerBufferedContribution {
    std::uint64_t packet_index {0};
    std::uint64_t flow_packet_index {0};
    std::vector<std::uint8_t> captured_bytes {};
    std::size_t original_byte_count {0U};
    std::uint32_t packet_captured_length {0U};
    std::uint32_t packet_original_length {0U};
};

struct TlsStreamScannerState {
    Direction direction {Direction::a_to_b};
    std::vector<TlsStreamScannerBufferedContribution> buffered_contributions {};
    std::optional<TlsStreamScannerPendingRecordState> pending_record {};
    bool post_change_cipher_spec {false};
    bool saw_tls_context {false};
    TlsInspectionParserContext parser_context {};
    bool prefer_payload_partial_for_unrecognized_trailing_bytes {false};
    std::uint64_t ordinal_packet_index {0};
    std::uint32_t next_intra_packet_ordinal {0U};
};

struct TlsStreamScannerOutput {
    std::vector<TlsScannedStreamRow> stable_rows {};
    std::optional<TlsScannedStreamRow> provisional_row {};
    bool provisional_depends_on_more_input {false};
    bool budget_exhausted {false};
    bool malformed_boundary {false};
};

struct TlsStreamRetainedDirectionCandidate {
    TlsScannedStreamRow row {};
    StreamMaterializationStability stability {StreamMaterializationStability::stable};
};

struct TlsStreamRetainedDirectionFrontier {
    Direction direction {Direction::a_to_b};
    TlsStreamScannerState scanner_state {};
    std::size_t next_packet_offset {0U};
    std::size_t supplied_packet_count {0U};
    std::optional<TlsStreamRetainedDirectionCandidate> current_candidate {};
    bool terminal {false};
};

struct TlsStreamRetainedFrontier {
    bool eligible {false};
    TlsStreamRetainedDirectionFrontier direction_a {};
    TlsStreamRetainedDirectionFrontier direction_b {};
};

struct TlsPacketStreamPresentation {
    bool handled {false};
    std::vector<TlsStreamPresentationItem> items {};
};

struct TlsDirectionalStreamPresentation {
    bool used_reassembly {false};
    bool explicit_gap_item_emitted {false};
    std::uint64_t first_gap_packet_index {0};
    std::string fallback_label {};
    std::set<std::uint64_t> covered_packet_indices {};
    std::vector<TlsStreamPresentationItem> items {};
};

[[nodiscard]] TlsStreamScannerState make_tls_stream_scanner_state(
    Direction direction,
    bool prefer_payload_partial_for_unrecognized_trailing_bytes = false
);

TlsStreamScannerOutput consume_tls_stream_scanner(
    TlsStreamScannerState& state,
    std::span<const TlsStreamScannerContribution> contributions,
    std::size_t max_finalized_items,
    TlsStreamScannerFinishMode finish_mode
);

struct TlsSelectedPacketContribution {
    std::uint64_t packet_index {0};
    // Internal flow-packet index is zero-based; summary/UI formatting adds +1.
    std::uint64_t flow_packet_index {0};
    std::size_t record_offset {0U};
    std::size_t captured_byte_count {0U};
};

enum class TlsSelectedPacketStatus : std::uint8_t {
    complete = 0,
    incomplete_window,
    tcp_gap,
    capture_constricted,
    malformed,
};

struct TlsSelectedPacketRecordContext {
    std::string label {};
    std::string protocol_text {};
    std::vector<std::uint8_t> captured_bytes {};
    std::size_t total_record_size {0U};
    TlsStreamItemSemanticKind semantic_kind {TlsStreamItemSemanticKind::none};
    TlsInspectionParserContext initial_parser_context {};
    TlsSelectedPacketStatus status {TlsSelectedPacketStatus::complete};
    std::vector<TlsSelectedPacketContribution> contributions {};
    std::optional<std::uint64_t> selected_contribution_flow_packet_index {};
    std::optional<std::uint64_t> completion_flow_packet_index {};
    bool has_constricted_contribution {false};
    std::vector<std::string> constricted_contribution_notes {};
    std::vector<std::string> constricted_packet_notes {};
};

struct TlsSelectedPacketAnalysis {
    TlsInspectionParserContext initial_parser_context {
        .semantic_state = TlsInspectionSemanticState::unknown,
    };
    std::vector<TlsSelectedPacketRecordContext> reconstructed_records {};
};

TlsPacketStreamPresentation build_tls_stream_items_for_packet(
    std::uint64_t packet_index,
    std::span<const std::uint8_t> payload_bytes
);

TlsDirectionalStreamPresentation build_tls_stream_items_from_reassembly(
    const CaptureSession& session,
    std::size_t flow_index,
    Direction direction,
    std::span<const PacketRef> direction_packets
);

TlsDirectionalStreamPresentation build_tls_stream_items_from_reassembly_bounded(
    const CaptureSession& session,
    std::size_t flow_index,
    Direction direction,
    std::span<const PacketRef> direction_packets,
    std::size_t skip_item_count,
    std::size_t max_item_count
);

TlsSelectedPacketAnalysis analyze_selected_packet_tls_contexts(
    CaptureSession& session,
    std::size_t flow_index,
    // Zero-based selected flow-packet index within the loaded flow packet window.
    std::uint64_t selected_flow_packet_index,
    std::size_t loaded_packet_window_count
);

std::vector<TlsSelectedPacketRecordContext> build_selected_packet_tls_contexts(
    CaptureSession& session,
    std::size_t flow_index,
    // Zero-based selected flow-packet index within the loaded flow packet window.
    std::uint64_t selected_flow_packet_index,
    std::size_t loaded_packet_window_count
);

std::optional<std::string> derive_tls_service_hint_for_loaded_flow_prefix(
    CaptureSession& session,
    std::size_t flow_index,
    std::size_t loaded_packet_window_count
);

}  // namespace session_detail
}  // namespace pfl
