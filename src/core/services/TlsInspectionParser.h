#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "core/services/TlsInspectionModel.h"

namespace pfl {

struct TlsRecordHeaderInspection {
    TlsRecordContentTypeKind content_type_kind {TlsRecordContentTypeKind::unknown};
    std::uint16_t legacy_version {0U};
    std::uint16_t declared_payload_length {0U};
    std::size_t total_size {0U};
    bool complete_record_available {false};
};

[[nodiscard]] std::optional<TlsRecordHeaderInspection> inspect_tls_record_header(
    std::span<const std::uint8_t> tls_bytes
) noexcept;

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
