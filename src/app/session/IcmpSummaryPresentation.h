#pragma once

#include <optional>

#include "app/session/SessionFormatting.h"

namespace pfl::session_detail {

std::optional<PacketSummaryLayer> build_icmp_summary_layer(const PacketDetails& details);

}  // namespace pfl::session_detail
