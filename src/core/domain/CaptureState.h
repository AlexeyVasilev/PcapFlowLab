#pragma once

#include <string>
#include <vector>

#include "core/domain/CapturePacketSizeStatistics.h"
#include "core/domain/CaptureSummary.h"
#include "core/domain/ConnectionTable.h"
#include "core/domain/PacketRef.h"
#include "core/domain/ProtocolPath.h"

namespace pfl {

struct UnrecognizedPacketRecord {
    PacketRef packet {};
    std::string reason_text {};
};

struct CapturePacketLocatorEntry {
    std::uint64_t packet_index {0};
    std::uint64_t file_offset {0};
};

struct CaptureState {
    ConnectionTableV4 ipv4_connections {};
    ConnectionTableV6 ipv6_connections {};
    std::vector<UnrecognizedPacketRecord> unrecognized_packets {};
    std::vector<CapturePacketLocatorEntry> packet_locator {};
    ProtocolPathRegistry protocol_path_registry {};
    CapturePacketStatistics packet_statistics {};
    CaptureSummary summary {};
};

}  // namespace pfl
