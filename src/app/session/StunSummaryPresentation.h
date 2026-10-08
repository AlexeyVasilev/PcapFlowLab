#pragma once

#include <optional>

#include "app/session/SessionFormatting.h"
#include "core/domain/StunInspection.h"

namespace pfl::session_detail {

[[nodiscard]] std::optional<PacketSummaryLayer> build_stun_summary_layer(const StunMessage& message);

}  // namespace pfl::session_detail
