#pragma once

#include <cstdint>
#include <string>

#include "core/domain/Connection.h"

namespace pfl {

struct FlowAnalysisResult {
    std::uint64_t total_packets {0};
    std::uint64_t total_bytes {0};
    std::uint64_t duration_us {0};
    std::uint64_t packets_a_to_b {0};
    std::uint64_t packets_b_to_a {0};
    std::uint64_t bytes_a_to_b {0};
    std::uint64_t bytes_b_to_a {0};
    std::string protocol_hint {};
    std::string service_hint {};
};

class FlowAnalysisService {
public:
    [[nodiscard]] FlowAnalysisResult analyze(const ConnectionV4& connection) const;
    [[nodiscard]] FlowAnalysisResult analyze(const ConnectionV6& connection) const;
};

}  // namespace pfl
