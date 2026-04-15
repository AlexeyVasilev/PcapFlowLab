#pragma once

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "core/domain/Direction.h"

namespace pfl {

class CaptureSession;

namespace session_detail {

struct HttpStreamPresentationItem {
    std::string label {};
    std::size_t byte_count {0U};
    std::vector<std::uint64_t> packet_indices {};
    std::string payload_hex_text {};
    std::string protocol_text {};
};

struct HttpDirectionalStreamPresentation {
    bool used_reassembly {false};
    bool explicit_gap_item_emitted {false};
    std::uint64_t first_gap_packet_index {0};
    std::string fallback_label {};
    std::string fallback_protocol_text {};
    std::set<std::uint64_t> covered_packet_indices {};
    std::vector<HttpStreamPresentationItem> items {};
};

HttpDirectionalStreamPresentation build_http_stream_items_from_reassembly(
    const CaptureSession& session,
    std::size_t flow_index,
    Direction direction,
    std::size_t max_packets_to_scan
);

std::string http_stream_label_from_protocol_text(std::string_view protocol_text);

}  // namespace session_detail
}  // namespace pfl
