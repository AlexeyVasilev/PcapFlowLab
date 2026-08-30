#include "app/frontend/FrontendStatisticsOverview.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <string_view>

#include "app/session/SessionFlowHelpers.h"

namespace pfl {

namespace {

constexpr std::string_view kUnavailableText {"—"};
constexpr std::string_view kOriginalByteDirectionHelpText {
    "Flows grouped by directional original-byte balance."
};
constexpr std::string_view kTcpFlagHelpText {
    "Counts TCP packets with the corresponding flag set. A packet may contribute to more than one row. SYN includes SYN+ACK."
};
constexpr std::uint64_t kMicrosPerSecond = 1'000'000ULL;
constexpr std::uint64_t kMicrosPerMinute = 60ULL * kMicrosPerSecond;
constexpr std::uint64_t kMicrosPerHour = 60ULL * kMicrosPerMinute;
constexpr std::uint64_t kMicrosPerDay = 24ULL * kMicrosPerHour;
constexpr std::uint64_t kMicrosPerMillisecond = 1'000ULL;

struct CivilDate {
    int year {0};
    unsigned month {0};
    unsigned day {0};
};

CivilDate civil_from_days(std::int64_t days_since_epoch) noexcept {
    days_since_epoch += 719468LL;
    const std::int64_t era = (days_since_epoch >= 0 ? days_since_epoch : days_since_epoch - 146096LL) / 146097LL;
    const unsigned day_of_era = static_cast<unsigned>(days_since_epoch - era * 146097LL);
    const unsigned year_of_era =
        (day_of_era - day_of_era / 1460U + day_of_era / 36524U - day_of_era / 146096U) / 365U;
    int year = static_cast<int>(year_of_era) + static_cast<int>(era) * 400;
    const unsigned day_of_year =
        day_of_era - (365U * year_of_era + year_of_era / 4U - year_of_era / 100U);
    const unsigned month_prime = (5U * day_of_year + 2U) / 153U;
    const unsigned day = day_of_year - (153U * month_prime + 2U) / 5U + 1U;
    const unsigned month = month_prime < 10U ? (month_prime + 3U) : (month_prime - 9U);
    year += month <= 2U ? 1 : 0;
    return CivilDate {.year = year, .month = month, .day = day};
}

std::string trim_trailing_zeros(std::string text) {
    const auto decimal_index = text.find('.');
    if (decimal_index == std::string::npos) {
        return text;
    }

    while (!text.empty() && text.back() == '0') {
        text.pop_back();
    }
    if (!text.empty() && text.back() == '.') {
        text.pop_back();
    }
    return text;
}

std::string group_integer_part(std::string text) {
    const auto decimal_index = text.find('.');
    const auto fraction = decimal_index == std::string::npos ? std::string {} : text.substr(decimal_index);
    std::string integer_part = decimal_index == std::string::npos ? std::move(text) : text.substr(0U, decimal_index);

    const bool negative = !integer_part.empty() && integer_part.front() == '-';
    if (negative) {
        integer_part.erase(integer_part.begin());
    }

    for (std::ptrdiff_t index = static_cast<std::ptrdiff_t>(integer_part.size()) - 3; index > 0; index -= 3) {
        integer_part.insert(static_cast<std::size_t>(index), " ");
    }

    if (negative) {
        integer_part.insert(integer_part.begin(), '-');
    }

    return integer_part + fraction;
}

double clamp_unit_fraction(double value) noexcept {
    if (!std::isfinite(value)) {
        return 0.0;
    }
    return std::clamp(value, 0.0, 1.0);
}

double percent_from_fraction(const double fraction) noexcept {
    return clamp_unit_fraction(fraction) * 100.0;
}

std::string format_display_size(const double value, const std::string_view suffix = {}) {
    static constexpr std::array<const char*, 5> units {"B", "KB", "MB", "GB", "TB"};

    double scaled = std::max(0.0, value);
    std::size_t unit_index = 0;
    while (scaled >= 1024.0 && unit_index + 1U < units.size()) {
        scaled /= 1024.0;
        ++unit_index;
    }

    if (unit_index == 0U) {
        const auto rounded = static_cast<std::uint64_t>(std::llround(scaled));
        return session_detail::format_statistics_count_value(rounded) + ' ' + units[unit_index] + std::string(suffix);
    }

    std::ostringstream out {};
    out << std::fixed << std::setprecision(1) << scaled;
    return group_integer_part(trim_trailing_zeros(out.str())) + ' ' + units[unit_index] + std::string(suffix);
}

std::string format_display_rate(
    const double value,
    const std::string_view suffix,
    const int max_fraction_digits
) {
    std::ostringstream out {};
    out << std::fixed << std::setprecision(max_fraction_digits) << std::max(0.0, value);
    return group_integer_part(trim_trailing_zeros(out.str())) + ' ' + std::string(suffix);
}

std::optional<std::string> format_absolute_utc_timestamp(const std::uint64_t value_us) {
    const auto days = static_cast<std::int64_t>(value_us / kMicrosPerDay);
    const auto time_us = value_us % kMicrosPerDay;
    const auto date = civil_from_days(days);
    if (date.year < 0 || date.year > 9999) {
        return std::nullopt;
    }

    const auto total_seconds = time_us / kMicrosPerSecond;
    const auto milliseconds = (time_us % kMicrosPerSecond) / kMicrosPerMillisecond;
    const auto hour = total_seconds / 3600ULL;
    const auto minute = (total_seconds % 3600ULL) / 60ULL;
    const auto second = total_seconds % 60ULL;

    char buffer[44] {};
    const int written = std::snprintf(
        buffer,
        sizeof(buffer),
        "%04d-%02u-%02u %02llu:%02llu:%02llu.%03llu UTC",
        date.year,
        date.month,
        date.day,
        static_cast<unsigned long long>(hour),
        static_cast<unsigned long long>(minute),
        static_cast<unsigned long long>(second),
        static_cast<unsigned long long>(milliseconds)
    );
    if (written <= 0) {
        return std::nullopt;
    }

    return std::string(buffer, static_cast<std::size_t>(written));
}

std::string format_duration_text(const std::uint64_t duration_us) {
    const auto days = duration_us / kMicrosPerDay;
    const auto remainder_after_days = duration_us % kMicrosPerDay;
    const auto hours = remainder_after_days / kMicrosPerHour;
    const auto remainder_after_hours = remainder_after_days % kMicrosPerHour;
    const auto minutes = remainder_after_hours / kMicrosPerMinute;
    const auto remainder_after_minutes = remainder_after_hours % kMicrosPerMinute;
    const auto seconds = remainder_after_minutes / kMicrosPerSecond;
    const auto milliseconds = (remainder_after_minutes % kMicrosPerSecond) / kMicrosPerMillisecond;

    std::ostringstream out {};
    if (days > 0U) {
        out << days << "d ";
    }
        out << std::setfill('0')
        << std::setw(2) << hours << ':'
        << std::setw(2) << minutes << ':'
        << std::setw(2) << seconds << '.'
        << std::setw(3) << milliseconds;
    return out.str();
}

std::string timestamp_text_or_unavailable(const std::optional<std::uint64_t>& timestamp_us) {
    if (!timestamp_us.has_value()) {
        return std::string {kUnavailableText};
    }

    const auto formatted = format_absolute_utc_timestamp(*timestamp_us);
    return formatted.value_or(std::string {kUnavailableText});
}

std::string duration_text_or_unavailable(const std::optional<std::uint64_t>& duration_us) {
    return duration_us.has_value()
        ? format_duration_text(*duration_us)
        : std::string {kUnavailableText};
}

std::string optional_size_text(const std::optional<double>& value) {
    return value.has_value() ? format_display_size(*value) : std::string {kUnavailableText};
}

std::string optional_packet_rate_text(const std::optional<double>& value) {
    return value.has_value() ? format_display_rate(*value, "pkt/s", 2) : std::string {kUnavailableText};
}

std::string optional_data_rate_text(const std::optional<double>& value) {
    return value.has_value() ? format_display_size(*value, "/s") : std::string {kUnavailableText};
}

std::string capture_completeness_text(
    const std::optional<double>& completeness,
    const std::uint64_t total_captured_bytes,
    const std::uint64_t total_original_bytes
) {
    if (!completeness.has_value() || total_original_bytes == 0U) {
        return std::string {kUnavailableText};
    }

    if (total_captured_bytes >= total_original_bytes) {
        return "100%";
    }

    constexpr double scale = 100.0;
    constexpr double max_fraction_digits_scale = 100.0;
    double visible_percent = std::floor(
        clamp_unit_fraction(*completeness) * scale * max_fraction_digits_scale
    ) / max_fraction_digits_scale;
    visible_percent = std::clamp(visible_percent, 0.0, 99.99);

    std::ostringstream out {};
    out << std::fixed << std::setprecision(2) << visible_percent;
    return trim_trailing_zeros(out.str()) + '%';
}

double safe_fraction(const std::uint64_t part, const std::uint64_t total) noexcept {
    if (part == 0U || total == 0U) {
        return 0.0;
    }

    return clamp_unit_fraction(static_cast<double>(part) / static_cast<double>(total));
}

FrontendDirectionDistributionRowDto make_direction_distribution_row(
    const std::string_view stable_id,
    const std::string_view label,
    const std::uint64_t flow_count,
    const std::uint64_t total_flow_count
) {
    const auto flow_fraction = safe_fraction(flow_count, total_flow_count);
    return FrontendDirectionDistributionRowDto {
        .stable_id = std::string(stable_id),
        .label = std::string(label),
        .flow_count = flow_count,
        .flow_fraction = flow_fraction,
        .flow_count_text = session_detail::format_statistics_count_value(flow_count),
        .percent_text = session_detail::format_statistics_percent_text(percent_from_fraction(flow_fraction)),
    };
}

FrontendTcpFlagStatisticsRowDto make_tcp_flag_statistics_row(
    const std::string_view stable_id,
    const std::string_view label,
    const std::uint64_t packet_count,
    const std::uint64_t total_tcp_packet_count
) {
    const auto packet_fraction = safe_fraction(packet_count, total_tcp_packet_count);
    return FrontendTcpFlagStatisticsRowDto {
        .stable_id = std::string(stable_id),
        .label = std::string(label),
        .packet_count = packet_count,
        .packet_fraction = packet_fraction,
        .packet_count_text = session_detail::format_statistics_count_value(packet_count),
        .percent_text = session_detail::format_statistics_percent_text(percent_from_fraction(packet_fraction)),
    };
}

}  // namespace

FrontendCaptureTimeStatisticsDto build_frontend_capture_time_statistics(
    const CapturePacketStatistics& packet_statistics
) {
    FrontendCaptureTimeStatisticsDto dto {};
    if (!packet_statistics.timestamp_range.available) {
        dto.capture_start_text = std::string {kUnavailableText};
        dto.capture_end_text = std::string {kUnavailableText};
        dto.duration_text = std::string {kUnavailableText};
        return dto;
    }

    dto.available = true;
    dto.capture_start_timestamp_us = packet_statistics.timestamp_range.earliest_timestamp_us;
    dto.capture_end_timestamp_us = packet_statistics.timestamp_range.latest_timestamp_us;
    dto.duration_us = packet_statistics.timestamp_range.latest_timestamp_us >=
            packet_statistics.timestamp_range.earliest_timestamp_us
        ? std::optional<std::uint64_t> {
            packet_statistics.timestamp_range.latest_timestamp_us -
            packet_statistics.timestamp_range.earliest_timestamp_us
        }
        : std::optional<std::uint64_t> {0U};
    dto.capture_start_text = timestamp_text_or_unavailable(dto.capture_start_timestamp_us);
    dto.capture_end_text = timestamp_text_or_unavailable(dto.capture_end_timestamp_us);
    dto.duration_text = duration_text_or_unavailable(dto.duration_us);
    return dto;
}

FrontendCaptureMetricsDto build_frontend_capture_metrics(
    const CapturePacketStatistics& packet_statistics
) {
    FrontendCaptureMetricsDto dto {};
    const auto total_packets = packet_statistics.total_packet_count;
    const auto total_captured_bytes = packet_statistics.total_captured_bytes;
    const auto total_original_bytes = packet_statistics.total_original_bytes;

    std::optional<std::uint64_t> duration_us {};
    if (packet_statistics.timestamp_range.available) {
        duration_us = packet_statistics.timestamp_range.latest_timestamp_us >=
                packet_statistics.timestamp_range.earliest_timestamp_us
            ? std::optional<std::uint64_t> {
                packet_statistics.timestamp_range.latest_timestamp_us -
                packet_statistics.timestamp_range.earliest_timestamp_us
            }
            : std::optional<std::uint64_t> {0U};
    }

    if (total_packets > 0U) {
        dto.average_captured_packet_size =
            static_cast<double>(total_captured_bytes) / static_cast<double>(total_packets);
        dto.average_original_packet_size =
            static_cast<double>(total_original_bytes) / static_cast<double>(total_packets);
    }

    if (duration_us.has_value() && *duration_us > 0U) {
        const auto seconds = static_cast<double>(*duration_us) / static_cast<double>(kMicrosPerSecond);
        dto.average_packet_rate = static_cast<double>(total_packets) / seconds;
        dto.average_captured_data_rate = static_cast<double>(total_captured_bytes) / seconds;
        dto.average_original_data_rate = static_cast<double>(total_original_bytes) / seconds;
    }

    dto.truncated_packet_count = packet_statistics.truncated_packet_count;
    dto.truncated_packet_fraction = safe_fraction(packet_statistics.truncated_packet_count, total_packets);
    dto.not_captured_bytes = total_original_bytes > total_captured_bytes
        ? (total_original_bytes - total_captured_bytes)
        : 0U;
    if (total_original_bytes > 0U) {
        dto.capture_completeness = clamp_unit_fraction(
            static_cast<double>(std::min(total_captured_bytes, total_original_bytes)) /
            static_cast<double>(total_original_bytes)
        );
    }

    dto.average_captured_packet_size_text = optional_size_text(dto.average_captured_packet_size);
    dto.average_original_packet_size_text = optional_size_text(dto.average_original_packet_size);
    dto.average_packet_rate_text = optional_packet_rate_text(dto.average_packet_rate);
    dto.average_captured_data_rate_text = optional_data_rate_text(dto.average_captured_data_rate);
    dto.average_original_data_rate_text = optional_data_rate_text(dto.average_original_data_rate);
    dto.truncated_packets_text = session_detail::format_statistics_count_with_percent_text(
        dto.truncated_packet_count,
        percent_from_fraction(dto.truncated_packet_fraction)
    );
    dto.not_captured_bytes_text = session_detail::format_statistics_size_value(dto.not_captured_bytes);
    dto.capture_completeness_text = capture_completeness_text(
        dto.capture_completeness,
        total_captured_bytes,
        total_original_bytes
    );
    return dto;
}

FrontendFlowCharacteristicsDto build_frontend_flow_characteristics(
    const CaptureFlowCharacteristicsStatistics& flow_characteristics
) {
    FrontendFlowCharacteristicsDto dto {};
    dto.total_flow_count = flow_characteristics.total_flow_count;
    dto.only_a_to_b_flow_count = flow_characteristics.only_a_to_b_flow_count;
    dto.service_recognized_flow_count = flow_characteristics.service_recognized_flow_count;
    dto.only_a_to_b_flow_fraction = safe_fraction(dto.only_a_to_b_flow_count, dto.total_flow_count);
    dto.service_recognized_flow_fraction = safe_fraction(dto.service_recognized_flow_count, dto.total_flow_count);
    dto.only_a_to_b_flows_text = session_detail::format_statistics_count_with_percent_text(
        dto.only_a_to_b_flow_count,
        percent_from_fraction(dto.only_a_to_b_flow_fraction)
    );
    dto.service_recognized_flows_text = session_detail::format_statistics_count_with_percent_text(
        dto.service_recognized_flow_count,
        percent_from_fraction(dto.service_recognized_flow_fraction)
    );
    return dto;
}

FrontendDirectionDistributionDto build_frontend_packet_direction_distribution(
    const CaptureFlowCharacteristicsStatistics& flow_characteristics,
    const FlowDirectionDistributionStatistics& distribution
) {
    const auto total_flow_count = flow_characteristics.total_flow_count;
    return FrontendDirectionDistributionDto {
        .total_flow_count = total_flow_count,
        .rows = {
            make_direction_distribution_row(
                "mostly_a_to_b",
                "Mostly A -> B",
                distribution.mostly_a_to_b_flow_count,
                total_flow_count
            ),
            make_direction_distribution_row(
                "balanced",
                "Balanced",
                distribution.balanced_flow_count,
                total_flow_count
            ),
            make_direction_distribution_row(
                "mostly_b_to_a",
                "Mostly B -> A",
                distribution.mostly_b_to_a_flow_count,
                total_flow_count
            ),
        },
    };
}

FrontendDirectionDistributionDto build_frontend_original_byte_direction_distribution(
    const CaptureFlowCharacteristicsStatistics& flow_characteristics,
    const FlowDirectionDistributionStatistics& distribution
) {
    const auto total_flow_count = flow_characteristics.total_flow_count;
    return FrontendDirectionDistributionDto {
        .total_flow_count = total_flow_count,
        .help_text = std::string {kOriginalByteDirectionHelpText},
        .rows = {
            make_direction_distribution_row(
                "mostly_a_to_b",
                "Mostly A -> B",
                distribution.mostly_a_to_b_flow_count,
                total_flow_count
            ),
            make_direction_distribution_row(
                "balanced",
                "Balanced",
                distribution.balanced_flow_count,
                total_flow_count
            ),
            make_direction_distribution_row(
                "mostly_b_to_a",
                "Mostly B -> A",
                distribution.mostly_b_to_a_flow_count,
                total_flow_count
            ),
        },
    };
}

FrontendTcpFlagStatisticsDto build_frontend_tcp_flag_statistics(
    const CaptureTcpFlagStatistics& statistics,
    const std::uint64_t total_tcp_packet_count
) {
    return FrontendTcpFlagStatisticsDto {
        .has_tcp_packets = total_tcp_packet_count > 0U,
        .total_tcp_packet_count = total_tcp_packet_count,
        .help_text = std::string {kTcpFlagHelpText},
        .rows = {
            make_tcp_flag_statistics_row("syn", "SYN", statistics.syn_packet_count, total_tcp_packet_count),
            make_tcp_flag_statistics_row("fin", "FIN", statistics.fin_packet_count, total_tcp_packet_count),
            make_tcp_flag_statistics_row("rst", "RST", statistics.rst_packet_count, total_tcp_packet_count),
        },
    };
}

std::string build_frontend_statistics_partial_open_warning_text(const bool partial_open) {
    return partial_open
        ? "Statistics cover successfully imported packets only; the capture was opened partially."
        : std::string {};
}

}  // namespace pfl
