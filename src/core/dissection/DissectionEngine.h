#pragma once

#include <cstddef>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

using DissectionStepConsumerFn = void (*)(void* context, const DissectionStep& step);

struct DissectionConsumer {
    DissectionStepConsumerFn on_step {nullptr};
    void* context {nullptr};

    void consume(const DissectionStep& step) const noexcept;
};

inline constexpr std::size_t kDefaultMaxDissectionDepth = 48U;

struct DissectionEngineResult {
    StopReason stop_reason {StopReason::none};
    std::size_t step_count {0U};
    std::size_t traversed_depth {0U};
};

class DissectionEngine {
public:
    [[nodiscard]] DissectionEngineResult run(
        const DissectionRegistry& registry,
        const ProtocolSelector& root_selector,
        const PacketSlice& root_slice,
        const DissectionConsumer& consumer = {},
        std::size_t max_depth = kDefaultMaxDissectionDepth
    ) const noexcept;
};

}  // namespace pfl::dissection
