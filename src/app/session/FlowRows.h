#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

#include "core/domain/ConnectionKey.h"

namespace pfl {

enum class FlowAddressFamily : std::uint8_t {
    ipv4,
    ipv6
};

using FlowConnectionKey = std::variant<ConnectionKeyV4, ConnectionKeyV6>;

struct FlowRow {
    std::size_t index {0};
    FlowAddressFamily family {FlowAddressFamily::ipv4};
    FlowConnectionKey key {ConnectionKeyV4 {}};
    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};
};

struct PacketRow {
    std::uint64_t packet_index {0};
    std::string timestamp_text {};
    std::uint32_t captured_length {0};
    std::uint32_t original_length {0};
};

struct ProtocolStats {
    std::uint64_t flow_count {0};
    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};
};

struct CaptureProtocolSummary {
    ProtocolStats tcp {};
    ProtocolStats udp {};
    ProtocolStats other {};
    ProtocolStats ipv4 {};
    ProtocolStats ipv6 {};
};

struct TopEndpointRow {
    std::string endpoint {};
    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};
};

struct TopPortRow {
    std::uint16_t port {0};
    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};
};

struct CaptureTopSummary {
    std::vector<TopEndpointRow> endpoints_by_bytes {};
    std::vector<TopPortRow> ports_by_bytes {};
};

}  // namespace pfl
