#pragma once

#include <optional>

#include "core/reassembly/ReassemblyTypes.h"

namespace pfl {

class CaptureSession;

class ReassemblyService {
public:
    // Bounded v1 helper for interactive or analyzer-driven TCP payload concatenation
    // in packet order. This intentionally produces best-effort derived data rather
    // than transport-correct TCP stream reconstruction.
    [[nodiscard]] std::optional<ReassemblyResult> reassemble_tcp_payload(
        const CaptureSession& session,
        const ReassemblyRequest& request
    ) const;
};

}  // namespace pfl
