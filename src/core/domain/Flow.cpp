#include "core/domain/Flow.h"

namespace pfl {

bool FlowV4::empty() const noexcept {
    return packet_count == 0 && total_bytes == 0 && packets.empty();
}

bool FlowV6::empty() const noexcept {
    return packet_count == 0 && total_bytes == 0 && packets.empty();
}

}  // namespace pfl
