#include "app/session/NtpSummaryPresentation.h"

#include <array>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace pfl::session_detail {

namespace {

struct CivilDate {
    int year {1970};
    unsigned month {1U};
    unsigned day {1U};
};

PacketSummaryField make_summary_field(std::string label, std::string value) {
    return PacketSummaryField {
        .label = std::move(label),
        .value = std::move(value),
    };
}

std::string format_leap_indicator(const std::uint8_t value) {
    switch (value) {
    case 0U:
        return "No warning (0)";
    case 1U:
        return "Last minute has 61 seconds (1)";
    case 2U:
        return "Last minute has 59 seconds (2)";
    case 3U:
        return "Unsynchronized (3)";
    default:
        return "Unknown (" + std::to_string(value) + ")";
    }
}

std::string format_mode(const std::uint8_t value) {
    switch (value) {
    case 3U:
        return "Client (3)";
    case 4U:
        return "Server (4)";
    default:
        return "Unsupported (" + std::to_string(value) + ")";
    }
}

std::string format_power_of_two_seconds(const std::int8_t exponent) {
    if (exponent >= 0) {
        if (exponent >= 63) {
            return "2^" + std::to_string(static_cast<int>(exponent)) + " s";
        }
        return std::to_string(1ULL << static_cast<unsigned>(exponent)) + " s";
    }
    return "2^" + std::to_string(static_cast<int>(exponent)) + " s";
}

std::string format_poll(const std::int8_t value) {
    return std::to_string(static_cast<int>(value)) + " (" + format_power_of_two_seconds(value) + ")";
}

std::string format_precision(const std::int8_t value) {
    return std::to_string(static_cast<int>(value)) + " (" + format_power_of_two_seconds(value) + ")";
}

std::string format_fixed_16_16_magnitude(const bool negative, const std::uint64_t magnitude) {
    const auto integer = magnitude >> 16U;
    auto fraction = magnitude & 0xFFFFU;

    std::string result = negative ? "-" : "";
    result += std::to_string(integer);
    if (fraction != 0U) {
        result += '.';
        for (int digit = 0; digit < 6 && fraction != 0U; ++digit) {
            fraction *= 10U;
            result += static_cast<char>('0' + (fraction >> 16U));
            fraction &= 0xFFFFU;
        }
        while (result.size() > 1U && result.back() == '0') {
            result.pop_back();
        }
        if (!result.empty() && result.back() == '.') {
            result.pop_back();
        }
    }
    result += " s";
    return result;
}

std::string format_fixed_16_16_signed(const std::uint32_t raw) {
    const auto signed_raw = raw <= 0x7FFFFFFFU
        ? static_cast<std::int64_t>(raw)
        : static_cast<std::int64_t>(raw) - 0x100000000LL;
    const bool negative = signed_raw < 0;
    const auto magnitude = static_cast<std::uint64_t>(negative ? -signed_raw : signed_raw);
    return format_fixed_16_16_magnitude(negative, magnitude);
}

std::string format_fixed_16_16_unsigned(const std::uint32_t raw) {
    return format_fixed_16_16_magnitude(false, raw);
}

std::string format_ntp_short_by_version(const std::uint8_t version, const std::uint32_t raw) {
    return version == 3U
        ? format_fixed_16_16_signed(raw)
        : format_fixed_16_16_unsigned(raw);
}

std::string format_stratum(const std::uint8_t version, const std::uint8_t stratum) {
    if (version == 4U) {
        if (stratum == 0U) {
            return "Unspecified or invalid (0)";
        }
        if (stratum == 1U) {
            return "Primary reference (1)";
        }
        if (stratum <= 15U) {
            return "Secondary reference (" + std::to_string(stratum) + ")";
        }
        if (stratum == 16U) {
            return "Unsynchronized (16)";
        }
    }

    if (stratum == 0U) {
        return "Unspecified (0)";
    }
    if (stratum == 1U) {
        return "Primary reference (1)";
    }
    return "Secondary reference (" + std::to_string(stratum) + ")";
}

bool is_printable_reference_id(const std::array<std::uint8_t, 4>& value) noexcept {
    for (const auto byte : value) {
        if (byte == 0U) {
            continue;
        }
        if (byte < 0x20U || byte > 0x7EU) {
            return false;
        }
    }
    return true;
}

std::string format_ascii_reference_id(const std::array<std::uint8_t, 4>& value) {
    std::string text {};
    for (const auto byte : value) {
        if (byte == 0U) {
            break;
        }
        text.push_back(static_cast<char>(byte));
    }
    return text;
}

std::string format_reference_id_as_ipv4(const std::array<std::uint8_t, 4>& value) {
    return std::to_string(value[0]) + '.' +
        std::to_string(value[1]) + '.' +
        std::to_string(value[2]) + '.' +
        std::to_string(value[3]);
}

std::string format_reference_id_as_hex(const std::array<std::uint8_t, 4>& value) {
    std::ostringstream builder {};
    builder << "0x" << std::hex << std::uppercase << std::setfill('0');
    for (const auto byte : value) {
        builder << std::setw(2) << static_cast<unsigned>(byte);
    }
    return builder.str();
}

std::string format_reference_id(
    const NtpMessage& message,
    const NetworkAddressFamily terminal_address_family
) {
    if (message.stratum <= 1U && is_printable_reference_id(message.reference_id)) {
        const auto text = format_ascii_reference_id(message.reference_id);
        if (!text.empty()) {
            return text;
        }
    }

    if (message.stratum > 1U && terminal_address_family == NetworkAddressFamily::ipv4) {
        return format_reference_id_as_ipv4(message.reference_id);
    }

    return format_reference_id_as_hex(message.reference_id);
}

CivilDate civil_from_days(const std::int64_t days_since_unix_epoch) noexcept {
    auto z = days_since_unix_epoch + 719468;
    const auto era = (z >= 0 ? z : z - 146096) / 146097;
    const auto doe = static_cast<unsigned>(z - era * 146097);
    const auto yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    auto y = static_cast<int>(yoe) + static_cast<int>(era) * 400;
    const auto doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const auto mp = (5 * doy + 2) / 153;
    const auto d = doy - (153 * mp + 2) / 5 + 1;
    const auto m = mp < 10 ? mp + 3 : mp - 9;
    y += m <= 2 ? 1 : 0;
    return CivilDate {
        .year = y,
        .month = m,
        .day = d,
    };
}

std::string format_timestamp(const NtpTimestamp& timestamp) {
    if (timestamp.seconds == 0U && timestamp.fraction == 0U) {
        return "Unspecified";
    }

    auto seconds = static_cast<std::uint64_t>(timestamp.seconds);
    auto microseconds =
        ((static_cast<std::uint64_t>(timestamp.fraction) * 1'000'000ULL) + 0x80000000ULL) >> 32U;
    if (microseconds == 1'000'000ULL) {
        ++seconds;
        microseconds = 0U;
    }

    const auto days_since_1900 = static_cast<std::int64_t>(seconds / 86400ULL);
    const auto seconds_of_day = static_cast<unsigned>(seconds % 86400ULL);
    const auto date = civil_from_days(days_since_1900 - 25567);
    const auto hour = seconds_of_day / 3600U;
    const auto minute = (seconds_of_day % 3600U) / 60U;
    const auto second = seconds_of_day % 60U;

    std::ostringstream builder {};
    builder << std::setfill('0')
            << std::setw(4) << date.year << '-'
            << std::setw(2) << date.month << '-'
            << std::setw(2) << date.day << ' '
            << std::setw(2) << hour << ':'
            << std::setw(2) << minute << ':'
            << std::setw(2) << second << '.'
            << std::setw(6) << microseconds
            << " UTC";
    return builder.str();
}

}  // namespace

std::optional<PacketSummaryLayer> build_ntp_summary_layer(
    const NtpMessage& message,
    const NetworkAddressFamily terminal_address_family
) {
    std::vector<PacketSummaryField> fields {
        make_summary_field("Leap Indicator", format_leap_indicator(message.leap_indicator)),
        make_summary_field("Version", std::to_string(message.version)),
        make_summary_field("Mode", format_mode(message.mode)),
        make_summary_field("Stratum", format_stratum(message.version, message.stratum)),
        make_summary_field("Poll", format_poll(message.poll)),
        make_summary_field("Precision", format_precision(message.precision)),
        make_summary_field("Root Delay", format_ntp_short_by_version(message.version, message.root_delay_raw)),
        make_summary_field("Root Dispersion", format_ntp_short_by_version(message.version, message.root_dispersion_raw)),
        make_summary_field("Reference ID", format_reference_id(message, terminal_address_family)),
        make_summary_field("Reference Timestamp", format_timestamp(message.reference_timestamp)),
        make_summary_field("Originate Timestamp", format_timestamp(message.originate_timestamp)),
        make_summary_field("Receive Timestamp", format_timestamp(message.receive_timestamp)),
        make_summary_field("Transmit Timestamp", format_timestamp(message.transmit_timestamp)),
    };

    if (message.version == 4U && message.stratum == 0U && is_printable_reference_id(message.reference_id)) {
        const auto kiss_code = format_ascii_reference_id(message.reference_id);
        if (!kiss_code.empty()) {
            fields.push_back(make_summary_field("Kiss Code", kiss_code));
        }
    }

    return PacketSummaryLayer {
        .id = "ntp",
        .title = "Network Time Protocol",
        .fields = std::move(fields),
    };
}

}  // namespace pfl::session_detail
