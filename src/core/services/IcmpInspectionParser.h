#pragma once

#include <cstddef>
#include <optional>
#include <span>

#include "core/domain/IcmpInspection.h"

namespace pfl {

class IcmpInspectionParser {
public:
    [[nodiscard]] IcmpMessage inspect(
        std::span<const std::uint8_t> icmp_bytes,
        std::optional<std::size_t> declared_length = {}
    ) const;
};

[[nodiscard]] bool icmp_common_header_complete(const IcmpMessage& message) noexcept;

}  // namespace pfl
