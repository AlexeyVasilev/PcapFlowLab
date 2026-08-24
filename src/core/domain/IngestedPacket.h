#pragma once

#include <optional>

#include "core/domain/FlowKey.h"
#include "core/domain/PacketRef.h"

namespace pfl {

struct PacketImportMetadata {
    std::optional<std::uint32_t> transport_payload_length {};
    std::optional<std::uint8_t> tcp_flags {};
    bool is_ip_fragmented {false};
};

struct IngestedPacketV4 {
    FlowKeyV4 flow_key {};
    PacketRef packet_ref {};
    PacketImportMetadata import_metadata {};
};

struct IngestedPacketV6 {
    FlowKeyV6 flow_key {};
    PacketRef packet_ref {};
    PacketImportMetadata import_metadata {};
};

}  // namespace pfl
