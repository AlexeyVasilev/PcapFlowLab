#include "core/domain/CaptureSummary.h"

namespace pfl {

bool CaptureSummary::empty() const noexcept {
    return packet_count == 0 && flow_count == 0 && total_bytes == 0;
}

}  // namespace pfl
