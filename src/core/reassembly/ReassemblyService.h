#pragma once

#include <optional>

#include "core/reassembly/ReassemblyTypes.h"

namespace pfl {

class CaptureSession;

class ReassemblyService {
public:
    // Deep-only v1 helper for bounded TCP payload concatenation in packet order.
    // This intentionally produces analyzer-oriented best-effort data rather than
    // transport-correct TCP stream reconstruction.
    [[nodiscard]] std::optional<ReassemblyResult> reassemble_tcp_payload(
        const CaptureSession& session,
        const ReassemblyRequest& request
    ) const;
};

}  // namespace pfl

