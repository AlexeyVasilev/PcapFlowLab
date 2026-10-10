#pragma once

#include <optional>
#include <string>

#include "app/session/SessionFormatting.h"
#include "core/domain/DhcpInspection.h"

namespace pfl::session_detail {

[[nodiscard]] std::string build_dhcp_stream_label(const DhcpMessage& message);
[[nodiscard]] std::optional<PacketSummaryLayer> build_dhcp_summary_layer(const DhcpMessage& message);

}  // namespace pfl::session_detail
