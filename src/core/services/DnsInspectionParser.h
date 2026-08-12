#pragma once

#include <span>

#include "core/domain/DnsInspection.h"

namespace pfl {

class DnsInspectionParser {
public:
    [[nodiscard]] DnsMessage inspect(std::span<const std::uint8_t> dns_bytes) const;
};

}  // namespace pfl
