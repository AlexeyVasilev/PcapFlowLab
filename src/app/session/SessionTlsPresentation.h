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

namespace pfl {

class CaptureSession;

namespace session_detail {

struct TlsStreamPresentationItem {
    std::string label {};
    std::size_t byte_count {0U};
    std::vector<std::uint64_t> packet_indices {};
    bool has_constricted_contribution {false};
    std::vector<std::string> constricted_contribution_notes {};
    std::vector<std::string> constricted_packet_notes {};
    std::string payload_hex_text {};
    std::string protocol_text {};
    TlsStreamItemSemanticKind semantic_kind {TlsStreamItemSemanticKind::none};
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
    std::string fallback_protocol_text {};
    std::set<std::uint64_t> covered_packet_indices {};
    std::vector<TlsStreamPresentationItem> items {};
};

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
    TlsSelectedPacketStatus status {TlsSelectedPacketStatus::complete};
    std::vector<TlsSelectedPacketContribution> contributions {};
    std::optional<std::uint64_t> selected_contribution_flow_packet_index {};
    std::optional<std::uint64_t> completion_flow_packet_index {};
    bool has_constricted_contribution {false};
    std::vector<std::string> constricted_contribution_notes {};
    std::vector<std::string> constricted_packet_notes {};
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

std::vector<TlsSelectedPacketRecordContext> build_selected_packet_tls_contexts(
    CaptureSession& session,
    std::size_t flow_index,
    // Zero-based selected flow-packet index within the loaded flow packet window.
    std::uint64_t selected_flow_packet_index,
    std::size_t loaded_packet_window_count
);

std::string tls_stream_label_from_protocol_text(std::string_view protocol_text);

}  // namespace session_detail
}  // namespace pfl
