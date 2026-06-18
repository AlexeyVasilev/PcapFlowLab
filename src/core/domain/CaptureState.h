#pragma once

#include <string>
#include <vector>

#include "core/domain/CaptureSummary.h"
#include "core/domain/ConnectionTable.h"
#include "core/domain/PacketRef.h"

namespace pfl {

struct UnrecognizedPacketRecord {
    PacketRef packet {};
    std::string reason_text {};
};

struct CaptureState {
    ConnectionTableV4 ipv4_connections {};
    ConnectionTableV6 ipv6_connections {};
    std::vector<UnrecognizedPacketRecord> unrecognized_packets {};
    CaptureSummary summary {};
};

}  // namespace pfl
