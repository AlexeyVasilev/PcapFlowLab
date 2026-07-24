#pragma once

#include <cstddef>

namespace pfl {

struct TerminalTransportPayloadBounds {
    std::size_t payload_offset {0U};
    std::size_t declared_end_offset {0U};

    [[nodiscard]] friend constexpr bool operator==(
        const TerminalTransportPayloadBounds&,
        const TerminalTransportPayloadBounds&
    ) = default;
};

}  // namespace pfl
