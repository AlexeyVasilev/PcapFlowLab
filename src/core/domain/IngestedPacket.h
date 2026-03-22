#pragma once

#include "core/domain/FlowKey.h"
#include "core/domain/PacketRef.h"

namespace pfl {

struct IngestedPacketV4 {
    FlowKeyV4 flow_key {};
    PacketRef packet_ref {};
};

struct IngestedPacketV6 {
    FlowKeyV6 flow_key {};
    PacketRef packet_ref {};
};

}  // namespace pfl
