#pragma once

#include <cstddef>
#include <cstdint>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

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

std::string tls_stream_label_from_protocol_text(std::string_view protocol_text);

}  // namespace session_detail
}  // namespace pfl
