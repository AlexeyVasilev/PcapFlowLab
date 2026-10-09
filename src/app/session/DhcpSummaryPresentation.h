#pragma once

#include <optional>

#include "app/session/SessionFormatting.h"
#include "core/domain/DhcpInspection.h"

namespace pfl::session_detail {

[[nodiscard]] std::optional<PacketSummaryLayer> build_dhcp_summary_layer(const DhcpMessage& message);

}  // namespace pfl::session_detail
