#pragma once

#include <optional>

#include "app/session/SessionFormatting.h"
#include "core/domain/NtpInspection.h"

namespace pfl::session_detail {

std::optional<PacketSummaryLayer> build_ntp_summary_layer(
    const NtpMessage& message,
    NetworkAddressFamily terminal_address_family
);

}  // namespace pfl::session_detail
