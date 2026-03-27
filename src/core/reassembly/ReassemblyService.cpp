#include "core/reassembly/ReassemblyService.h"

namespace pfl {

std::optional<ReassemblyResult> ReassemblyService::reassemble_tcp_payload(
    const CaptureSession&,
    const ReassemblyRequest&
) const {
    // Stub only. This service must remain a derived-artifact producer:
    // it does not mutate CaptureState, does not update hints, does not write
    // indexes/checkpoints, and does not introduce background processing.
    return std::nullopt;
}

}  // namespace pfl
