#pragma once

#include <optional>

#include "app/session/SessionFormatting.h"

namespace pfl::session_detail {

std::optional<PacketSummaryLayer> build_dns_summary_layer(
    const PacketDetails& details,
    DnsSummaryPresentationKind presentation_kind
);

}  // namespace pfl::session_detail
