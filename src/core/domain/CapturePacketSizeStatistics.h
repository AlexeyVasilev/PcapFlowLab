#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include "core/domain/PacketRef.h"

namespace pfl {

struct CapturePacketSizeStatisticsBucket {
    std::string_view stable_id {};
    std::uint32_t lower_bound_inclusive {0};
    std::optional<std::uint32_t> upper_bound_inclusive {};
    std::uint64_t packet_count {0};
};

inline constexpr std::size_t kCapturePacketSizeStatisticsBucketCount = 13U;

constexpr std::array<CapturePacketSizeStatisticsBucket, kCapturePacketSizeStatisticsBucketCount>
make_captured_packet_size_statistics_buckets() {
    return {{
        {"captured_bytes_0_63", 0U, 63U, 0U},
        {"captured_bytes_64_127", 64U, 127U, 0U},
        {"captured_bytes_128_255", 128U, 255U, 0U},
        {"captured_bytes_256_511", 256U, 511U, 0U},
        {"captured_bytes_512_1023", 512U, 1023U, 0U},
        {"captured_bytes_1024_1399", 1024U, 1399U, 0U},
        {"captured_bytes_1400_1550", 1400U, 1550U, 0U},
        {"captured_bytes_1551_2499", 1551U, 2499U, 0U},
        {"captured_bytes_2500_5000", 2500U, 5000U, 0U},
        {"captured_bytes_5001_9000", 5001U, 9000U, 0U},
        {"captured_bytes_9001_16000", 9001U, 16000U, 0U},
        {"captured_bytes_16001_25000", 16001U, 25000U, 0U},
        {"captured_bytes_25001_plus", 25001U, std::nullopt, 0U},
    }};
}

constexpr std::array<CapturePacketSizeStatisticsBucket, kCapturePacketSizeStatisticsBucketCount>
make_original_packet_size_statistics_buckets() {
    return {{
        {"original_bytes_0_63", 0U, 63U, 0U},
        {"original_bytes_64_127", 64U, 127U, 0U},
        {"original_bytes_128_255", 128U, 255U, 0U},
        {"original_bytes_256_511", 256U, 511U, 0U},
        {"original_bytes_512_1023", 512U, 1023U, 0U},
        {"original_bytes_1024_1399", 1024U, 1399U, 0U},
        {"original_bytes_1400_1550", 1400U, 1550U, 0U},
        {"original_bytes_1551_2499", 1551U, 2499U, 0U},
        {"original_bytes_2500_5000", 2500U, 5000U, 0U},
        {"original_bytes_5001_9000", 5001U, 9000U, 0U},
        {"original_bytes_9001_16000", 9001U, 16000U, 0U},
        {"original_bytes_16001_25000", 16001U, 25000U, 0U},
        {"original_bytes_25001_plus", 25001U, std::nullopt, 0U},
    }};
}

struct CapturePacketSizeDistribution {
    std::uint64_t maximum_bucket_packet_count {0};
    std::array<CapturePacketSizeStatisticsBucket, kCapturePacketSizeStatisticsBucketCount> buckets {
        make_captured_packet_size_statistics_buckets()
    };
};

struct CapturePacketTimestampRange {
    bool available {false};
    std::uint64_t earliest_timestamp_us {0};
    std::uint64_t latest_timestamp_us {0};
};

struct CapturePacketStatistics {
    std::uint64_t total_packet_count {0};
    std::uint64_t total_captured_bytes {0};
    std::uint64_t total_original_bytes {0};
    CapturePacketTimestampRange timestamp_range {};
    std::uint64_t truncated_packet_count {0};
    std::uint32_t maximum_captured_packet_length {0};
    std::uint32_t maximum_original_packet_length {0};
    CapturePacketSizeDistribution captured_size_distribution {};
    CapturePacketSizeDistribution original_size_distribution {
        .maximum_bucket_packet_count = 0U,
        .buckets = make_original_packet_size_statistics_buckets(),
    };
    std::uint64_t unrecognized_packet_count {0};
    std::uint64_t unrecognized_captured_bytes {0};
    std::uint64_t unrecognized_original_bytes {0};
};

struct CapturePacketSizeStatistics {
    std::uint64_t total_packet_count {0};
    std::uint64_t total_captured_bytes {0};
    std::uint64_t maximum_bucket_packet_count {0};
    std::uint32_t maximum_captured_packet_length {0};
    std::array<CapturePacketSizeStatisticsBucket, kCapturePacketSizeStatisticsBucketCount> buckets {
        make_captured_packet_size_statistics_buckets()
    };
};

constexpr std::size_t capture_packet_size_bucket_index(const std::uint32_t captured_length) noexcept {
    if (captured_length <= 63U) {
        return 0U;
    }
    if (captured_length <= 127U) {
        return 1U;
    }
    if (captured_length <= 255U) {
        return 2U;
    }
    if (captured_length <= 511U) {
        return 3U;
    }
    if (captured_length <= 1023U) {
        return 4U;
    }
    if (captured_length <= 1399U) {
        return 5U;
    }
    if (captured_length <= 1550U) {
        return 6U;
    }
    if (captured_length <= 2499U) {
        return 7U;
    }
    if (captured_length <= 5000U) {
        return 8U;
    }
    if (captured_length <= 9000U) {
        return 9U;
    }
    if (captured_length <= 16000U) {
        return 10U;
    }
    if (captured_length <= 25000U) {
        return 11U;
    }
    return 12U;
}

inline void accumulate_capture_packet_size(
    CapturePacketSizeStatistics& statistics,
    const std::uint32_t captured_length
) noexcept {
    const auto bucket_index = capture_packet_size_bucket_index(captured_length);
    auto& bucket = statistics.buckets[bucket_index];
    ++bucket.packet_count;
    ++statistics.total_packet_count;
    statistics.total_captured_bytes += captured_length;
    if (bucket.packet_count > statistics.maximum_bucket_packet_count) {
        statistics.maximum_bucket_packet_count = bucket.packet_count;
    }
    if (captured_length > statistics.maximum_captured_packet_length) {
        statistics.maximum_captured_packet_length = captured_length;
    }
}

inline void accumulate_capture_packet_size_distribution(
    CapturePacketSizeDistribution& distribution,
    const std::uint32_t packet_length
) noexcept {
    const auto bucket_index = capture_packet_size_bucket_index(packet_length);
    auto& bucket = distribution.buckets[bucket_index];
    ++bucket.packet_count;
    if (bucket.packet_count > distribution.maximum_bucket_packet_count) {
        distribution.maximum_bucket_packet_count = bucket.packet_count;
    }
}

constexpr std::uint64_t capture_packet_timestamp_us(const PacketRef& packet) noexcept {
    return (static_cast<std::uint64_t>(packet.ts_sec) * 1'000'000ULL) +
        static_cast<std::uint64_t>(packet.ts_usec);
}

inline void observe_capture_packet_statistics(
    CapturePacketStatistics& statistics,
    const PacketRef& packet,
    const bool recognized
) noexcept {
    ++statistics.total_packet_count;
    statistics.total_captured_bytes += packet.captured_length;
    statistics.total_original_bytes += packet.original_length;

    const auto timestamp_us = capture_packet_timestamp_us(packet);
    if (!statistics.timestamp_range.available) {
        statistics.timestamp_range = CapturePacketTimestampRange {
            .available = true,
            .earliest_timestamp_us = timestamp_us,
            .latest_timestamp_us = timestamp_us,
        };
    } else {
        if (timestamp_us < statistics.timestamp_range.earliest_timestamp_us) {
            statistics.timestamp_range.earliest_timestamp_us = timestamp_us;
        }
        if (timestamp_us > statistics.timestamp_range.latest_timestamp_us) {
            statistics.timestamp_range.latest_timestamp_us = timestamp_us;
        }
    }

    if (packet.captured_length < packet.original_length) {
        ++statistics.truncated_packet_count;
    }
    if (packet.captured_length > statistics.maximum_captured_packet_length) {
        statistics.maximum_captured_packet_length = packet.captured_length;
    }
    if (packet.original_length > statistics.maximum_original_packet_length) {
        statistics.maximum_original_packet_length = packet.original_length;
    }

    accumulate_capture_packet_size_distribution(
        statistics.captured_size_distribution,
        packet.captured_length
    );
    accumulate_capture_packet_size_distribution(
        statistics.original_size_distribution,
        packet.original_length
    );

    if (!recognized) {
        ++statistics.unrecognized_packet_count;
        statistics.unrecognized_captured_bytes += packet.captured_length;
        statistics.unrecognized_original_bytes += packet.original_length;
    }
}

inline CapturePacketSizeStatistics make_capture_packet_size_statistics(
    const CapturePacketStatistics& statistics
) noexcept {
    return CapturePacketSizeStatistics {
        .total_packet_count = statistics.total_packet_count,
        .total_captured_bytes = statistics.total_captured_bytes,
        .maximum_bucket_packet_count = statistics.captured_size_distribution.maximum_bucket_packet_count,
        .maximum_captured_packet_length = statistics.maximum_captured_packet_length,
        .buckets = statistics.captured_size_distribution.buckets,
    };
}

}  // namespace pfl
