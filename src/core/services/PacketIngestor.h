#pragma once

#include "core/domain/CaptureState.h"
#include "core/domain/Connection.h"
#include "core/domain/IngestedPacket.h"

namespace pfl {

class PacketIngestor {
public:
    explicit PacketIngestor(CaptureState& state) noexcept;

    ConnectionV4& ingest(const IngestedPacketV4& packet);
    ConnectionV6& ingest(const IngestedPacketV6& packet);

private:
    CaptureState& state_;
};

}  // namespace pfl
