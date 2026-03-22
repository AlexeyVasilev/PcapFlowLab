#pragma once

#include "core/domain/CaptureState.h"
#include "core/domain/IngestedPacket.h"

namespace pfl {

class PacketIngestor {
public:
    explicit PacketIngestor(CaptureState& state) noexcept;

    void ingest(const IngestedPacketV4& packet);
    void ingest(const IngestedPacketV6& packet);

private:
    CaptureState& state_;
};

}  // namespace pfl
