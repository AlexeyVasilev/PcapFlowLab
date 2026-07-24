#include "core/dissection/DissectionEngine.h"

namespace pfl::dissection {

void DissectionConsumer::consume(const DissectionStep& step) const noexcept {
    if (on_step != nullptr) {
        on_step(context, step);
    }
}

DissectionEngineResult DissectionEngine::run(
    const DissectionRegistry& registry,
    const ProtocolSelector& root_selector,
    const PacketSlice& root_slice,
    const DissectionConsumer& consumer,
    const std::size_t max_depth
) const noexcept {
    DissectionEngineResult result {};
    if (max_depth == 0U) {
        result.stop_reason = StopReason::depth_limit;
        return result;
    }

    auto current_selector = root_selector;
    auto current_slice = root_slice;

    for (std::size_t depth = 0U; depth < max_depth; ++depth) {
        const auto dissector = registry.find(current_selector);
        if (dissector == nullptr) {
            result.stop_reason = StopReason::unknown_next_protocol;
            return result;
        }

        const auto step = dissector(current_slice);
        consumer.consume(step);
        ++result.step_count;
        result.traversed_depth = depth + 1U;

        if (step.stop_reason != StopReason::none) {
            result.stop_reason = step.stop_reason;
            return result;
        }

        if (!step.handoff.has_value() || !step.handoff->child.has_value()) {
            result.stop_reason = StopReason::unknown_next_protocol;
            return result;
        }

        if (depth + 1U >= max_depth) {
            result.stop_reason = StopReason::depth_limit;
            return result;
        }

        current_selector = step.handoff->selector;
        current_slice = *step.handoff->child;
    }

    result.stop_reason = StopReason::depth_limit;
    return result;
}

}  // namespace pfl::dissection
