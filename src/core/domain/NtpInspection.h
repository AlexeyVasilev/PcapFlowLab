#pragma once

#include <array>
#include <cstdint>

namespace pfl {

struct NtpTimestamp {
    std::uint32_t seconds {0U};
    std::uint32_t fraction {0U};

    [[nodiscard]] friend constexpr bool operator==(const NtpTimestamp&, const NtpTimestamp&) = default;
};

struct NtpMessage {
    std::uint8_t leap_indicator {0U};
    std::uint8_t version {0U};
    std::uint8_t mode {0U};
    std::uint8_t stratum {0U};
    std::int8_t poll {0};
    std::int8_t precision {0};
    std::uint32_t root_delay_raw {0U};
    std::uint32_t root_dispersion_raw {0U};
    std::array<std::uint8_t, 4> reference_id {};
    NtpTimestamp reference_timestamp {};
    NtpTimestamp originate_timestamp {};
    NtpTimestamp receive_timestamp {};
    NtpTimestamp transmit_timestamp {};
};

}  // namespace pfl
