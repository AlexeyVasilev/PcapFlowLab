#pragma once

#include <cstdint>
#include <span>

#include "core/services/TlsInspectionModel.h"

namespace pfl {

class TlsInspectionParser {
public:
    [[nodiscard]] TlsInspectionResult inspect(
        std::span<const std::uint8_t> tls_bytes,
        TlsInspectionSemanticState initial_state = TlsInspectionSemanticState::plaintext
    ) const;
};

}  // namespace pfl
