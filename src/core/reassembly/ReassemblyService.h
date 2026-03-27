#pragma once

#include <optional>

#include "core/reassembly/ReassemblyTypes.h"

namespace pfl {

class CaptureSession;

class ReassemblyService {
public:
    // Architecture scaffold only. Real TCP payload reassembly is intentionally
    // deferred so deep analyzers can integrate against a stable service shape
    // without changing current runtime behavior.
    [[nodiscard]] std::optional<ReassemblyResult> reassemble_tcp_payload(
        const CaptureSession& session,
        const ReassemblyRequest& request
    ) const;
};

}  // namespace pfl
