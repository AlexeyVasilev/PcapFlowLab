#pragma once

#include <algorithm>
#include <cstdint>
#include <string_view>

namespace pfl {

enum class DirectionDistribution : std::uint8_t {
    mostly_a_to_b = 0,
    balanced,
    mostly_b_to_a,
};

constexpr DirectionDistribution classify_direction_distribution(
    const std::uint64_t a_to_b_value,
    const std::uint64_t b_to_a_value
) noexcept {
    if (a_to_b_value == 0U && b_to_a_value == 0U) {
        return DirectionDistribution::balanced;
    }
    if (b_to_a_value == 0U) {
        return DirectionDistribution::mostly_a_to_b;
    }
    if (a_to_b_value == 0U) {
        return DirectionDistribution::mostly_b_to_a;
    }

    const auto larger = std::max(a_to_b_value, b_to_a_value);
    const auto smaller = std::min(a_to_b_value, b_to_a_value);
    if ((larger - smaller) <= smaller) {
        return DirectionDistribution::balanced;
    }

    return a_to_b_value > b_to_a_value
        ? DirectionDistribution::mostly_a_to_b
        : DirectionDistribution::mostly_b_to_a;
}

constexpr std::string_view direction_distribution_stable_id(const DirectionDistribution value) noexcept {
    switch (value) {
    case DirectionDistribution::mostly_a_to_b:
        return "mostly_a_to_b";
    case DirectionDistribution::balanced:
        return "balanced";
    case DirectionDistribution::mostly_b_to_a:
        return "mostly_b_to_a";
    }
    return {};
}

}  // namespace pfl
