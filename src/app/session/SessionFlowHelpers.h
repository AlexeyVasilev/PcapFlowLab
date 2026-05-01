#pragma once

#include <vector>

#include "app/session/FlowRows.h"
#include "core/domain/CaptureState.h"
#include "core/services/AnalysisSettings.h"

namespace pfl::session_detail {

struct ListedConnectionRef {
    FlowAddressFamily family {FlowAddressFamily::ipv4};
    const ConnectionV4* ipv4 {nullptr};
    const ConnectionV6* ipv6 {nullptr};
};

std::vector<ListedConnectionRef> list_connections(const CaptureState& state);
std::uint64_t packet_count(const ListedConnectionRef& connection) noexcept;
std::uint64_t captured_bytes(const ListedConnectionRef& connection) noexcept;
std::uint64_t total_bytes(const ListedConnectionRef& connection) noexcept;
ProtocolId protocol_id(const ListedConnectionRef& connection) noexcept;
FlowProtocolHint effective_protocol_hint(const ListedConnectionRef& connection, const AnalysisSettings& settings) noexcept;
void add_protocol_stats(ProtocolStats& stats, const ListedConnectionRef& connection) noexcept;
std::vector<PacketRef> collect_packets(const ConnectionV4& connection);
std::vector<PacketRef> collect_packets(const ConnectionV6& connection);
FlowRow make_flow_row(std::size_t index, const ListedConnectionRef& connection, const AnalysisSettings& settings);

}  // namespace pfl::session_detail
