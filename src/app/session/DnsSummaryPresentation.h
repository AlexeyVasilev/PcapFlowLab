#pragma once

#include <optional>
#include <string>

#include "app/session/SessionFormatting.h"

namespace pfl::session_detail {

std::string format_dns_type_text(std::uint16_t type);
std::string format_dns_type_compact_text(std::uint16_t type);

std::optional<PacketSummaryLayer> build_dns_summary_layer(
    const DnsMessage& message,
    DnsSummaryPresentationKind presentation_kind
);

std::optional<PacketSummaryLayer> build_dns_summary_layer(
    const PacketDetails& details,
    DnsSummaryPresentationKind presentation_kind
);

}  // namespace pfl::session_detail
