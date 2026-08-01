#pragma once

#include <cstdint>
#include <span>

#include "core/services/TlsInspectionModel.h"

namespace pfl {

class TlsInspectionParser {
public:
    [[nodiscard]] TlsInspectionResult inspect(
        std::span<const std::uint8_t> tls_bytes,
        TlsInspectionParserContext initial_context = {}
    ) const;

    [[nodiscard]] std::vector<TlsHandshakeModel> inspect_handshake_messages(
        std::span<const std::uint8_t> handshake_bytes,
        TlsInspectionParserContext initial_context = {}
    ) const;

    [[nodiscard]] TlsInspectionResult inspect(
        std::span<const std::uint8_t> tls_bytes,
        TlsInspectionSemanticState initial_state
    ) const;
};

}  // namespace pfl
