#include "ui/app/AdvancedFlowFilterEditorModel.h"

#include "app/session/AdvancedFlowFilterFormat.h"
#include "app/session/ProtocolPathPresentation.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <limits>
#include <optional>
#include <type_traits>

#include <QHostAddress>
#include <QAbstractSocket>
#include <QVariantMap>

namespace pfl {

namespace {

template <typename T>
struct AdvancedFilterOptionDescriptor {
    T value {};
    const char* label {""};
    const char* object_name_suffix {""};
};

constexpr std::array<AdvancedFilterOptionDescriptor<FlowAddressFamily>, 2> kAdvancedFilterAddressFamilyOptions {{
    {FlowAddressFamily::ipv4, "IPv4", "Ipv4"},
    {FlowAddressFamily::ipv6, "IPv6", "Ipv6"},
}};

constexpr std::array<AdvancedFilterOptionDescriptor<ProtocolId>, 8> kAdvancedFilterFlowProtocolOptions {{
    {ProtocolId::tcp, "TCP", "Tcp"},
    {ProtocolId::udp, "UDP", "Udp"},
    {ProtocolId::sctp, "SCTP", "Sctp"},
    {ProtocolId::icmp, "ICMP", "Icmp"},
    {ProtocolId::icmpv6, "ICMPv6", "Icmpv6"},
    {ProtocolId::igmp, "IGMP", "Igmp"},
    {ProtocolId::arp, "ARP", "Arp"},
    {ProtocolId::esp, "ESP", "Esp"},
}};

constexpr std::array<AdvancedFilterOptionDescriptor<FlowProtocolHint>, 17> kAdvancedFilterDetectedProtocolOptions {{
    {FlowProtocolHint::unknown, "Unknown", "Unknown"},
    {FlowProtocolHint::tls, "TLS", "Tls"},
    {FlowProtocolHint::http, "HTTP", "Http"},
    {FlowProtocolHint::dns, "DNS", "Dns"},
    {FlowProtocolHint::quic, "QUIC", "Quic"},
    {FlowProtocolHint::ssh, "SSH", "Ssh"},
    {FlowProtocolHint::stun, "STUN", "Stun"},
    {FlowProtocolHint::bittorrent, "BitTorrent", "Bittorrent"},
    {FlowProtocolHint::dhcp, "DHCP", "Dhcp"},
    {FlowProtocolHint::mdns, "mDNS", "Mdns"},
    {FlowProtocolHint::smtp, "SMTP", "Smtp"},
    {FlowProtocolHint::pop3, "POP3", "Pop3"},
    {FlowProtocolHint::imap, "IMAP", "Imap"},
    {FlowProtocolHint::igmp, "IGMP", "Igmp"},
    {FlowProtocolHint::igmpv1, "IGMPv1", "Igmpv1"},
    {FlowProtocolHint::igmpv2, "IGMPv2", "Igmpv2"},
    {FlowProtocolHint::igmpv3, "IGMPv3", "Igmpv3"},
}};

constexpr std::array<AdvancedFilterOptionDescriptor<TlsVersionHint>, 3> kAdvancedFilterTlsVersionOptions {{
    {TlsVersionHint::tls12, "TLS 1.2", "Tls12"},
    {TlsVersionHint::tls13, "TLS 1.3", "Tls13"},
    {TlsVersionHint::unknown, "Unknown TLS/SSL", "UnknownTlsSsl"},
}};

constexpr std::array<AdvancedFilterOptionDescriptor<QuicVersionHint>, 4> kAdvancedFilterQuicVersionOptions {{
    {QuicVersionHint::v1, "QUIC v1", "QuicV1"},
    {QuicVersionHint::v2, "QUIC v2", "QuicV2"},
    {QuicVersionHint::draft29, "QUIC draft-29", "QuicDraft29"},
    {QuicVersionHint::unknown, "Unknown QUIC", "UnknownQuic"},
}};

constexpr std::array<AdvancedFilterOptionDescriptor<session_detail::AdvancedFlowFilterDirectionality>, 2>
    kAdvancedFilterDirectionalityOptions {{
        {session_detail::AdvancedFlowFilterDirectionality::unidirectional, "Only A -> B packets", "Unidirectional"},
        {session_detail::AdvancedFlowFilterDirectionality::bidirectional, "Packets in both directions", "Bidirectional"},
    }};

constexpr std::array<AdvancedFilterOptionDescriptor<DirectionDistribution>, 3>
    kAdvancedFilterTrafficDistributionOptions {{
        {DirectionDistribution::mostly_a_to_b, "Mostly A -> B", "MostlyAToB"},
        {DirectionDistribution::balanced, "Balanced", "Balanced"},
        {DirectionDistribution::mostly_b_to_a, "Mostly B -> A", "MostlyBToA"},
    }};

constexpr std::array<AdvancedFilterOptionDescriptor<session_detail::AdvancedFlowFilterPortScope>, 3>
    kAdvancedFlowFilterPortScopeOptions {{
        {session_detail::AdvancedFlowFilterPortScope::either_endpoint, "Either endpoint", "EitherEndpoint"},
        {session_detail::AdvancedFlowFilterPortScope::endpoint_a, "Endpoint A", "EndpointA"},
        {session_detail::AdvancedFlowFilterPortScope::endpoint_b, "Endpoint B", "EndpointB"},
    }};

constexpr std::array<AdvancedFilterOptionDescriptor<session_detail::AdvancedFlowFilterEndpointScope>, 3>
    kAdvancedFlowFilterAddressScopeOptions {{
        {session_detail::AdvancedFlowFilterEndpointScope::either_endpoint, "Either endpoint", "EitherEndpoint"},
        {session_detail::AdvancedFlowFilterEndpointScope::endpoint_a, "Endpoint A", "EndpointA"},
        {session_detail::AdvancedFlowFilterEndpointScope::endpoint_b, "Endpoint B", "EndpointB"},
    }};

constexpr std::array<AdvancedFilterOptionDescriptor<AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit>, 5>
    kAdvancedFlowFilterByteUnitOptions {{
        {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::bytes, "B", "Bytes"},
        {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::kib, "KiB", "KiB"},
        {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::mib, "MiB", "MiB"},
        {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::gib, "GiB", "GiB"},
        {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::tib, "TiB", "TiB"},
    }};

constexpr std::array<AdvancedFilterOptionDescriptor<AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit>, 2>
    kAdvancedFlowFilterPacketSizeUnitOptions {{
        {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::bytes, "B", "Bytes"},
        {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::kib, "KiB", "KiB"},
    }};

constexpr std::array<AdvancedFilterOptionDescriptor<AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit>, 5>
    kAdvancedFlowFilterDurationUnitOptions {{
        {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::microseconds, "us", "Us"},
        {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::milliseconds, "ms", "Ms"},
        {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::seconds, "s", "S"},
        {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::minutes, "min", "Min"},
        {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::hours, "h", "H"},
    }};

constexpr std::array<AdvancedFilterOptionDescriptor<session_detail::AdvancedFlowFilterServicePredicateKind>, 3>
    kAdvancedFlowFilterServiceOperatorOptions {{
        {session_detail::AdvancedFlowFilterServicePredicateKind::equals, "Equals", "Equals"},
        {session_detail::AdvancedFlowFilterServicePredicateKind::starts_with, "Starts with", "StartsWith"},
        {session_detail::AdvancedFlowFilterServicePredicateKind::contains, "Contains", "Contains"},
    }};

constexpr std::array<
    AdvancedFilterOptionDescriptor<AdvancedFlowFilterEditorModel::AdvancedFlowFilterContainsLayerIdentifierMode>,
    2>
    kAdvancedFlowFilterContainsLayerIdentifierModeOptions {{
        {AdvancedFlowFilterEditorModel::AdvancedFlowFilterContainsLayerIdentifierMode::any, "Any", "Any"},
        {AdvancedFlowFilterEditorModel::AdvancedFlowFilterContainsLayerIdentifierMode::exact, "Exact", "Exact"},
    }};

enum class TrafficMetricValueKind : std::uint8_t {
    count = 0,
    bytes_u64,
    bytes_u32,
    duration_us,
};

struct TrafficMetricDescriptor {
    AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric metric {};
    const char* label {""};
    const char* object_name_prefix {""};
    AdvancedFlowFilterEditorModel::TrafficRowGroup group {
        AdvancedFlowFilterEditorModel::TrafficRowGroup::primary
    };
    TrafficMetricValueKind value_kind {TrafficMetricValueKind::count};
};

struct TimeRangeDescriptor {
    const char* metric_id {""};
    const char* label {""};
    const char* object_name_prefix {""};
};

constexpr std::array<TimeRangeDescriptor, 3> kTimeRangeDescriptors {{
    {"start", "Flow start", "TimeStart"},
    {"end", "Flow end", "TimeEnd"},
    {"overlap", "Flow lifetime overlaps", "TimeOverlap"},
}};

constexpr TrafficMetricDescriptor kTimeDurationDescriptor {
    AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::packet_count,
    "Duration",
    "TimeDuration",
    AdvancedFlowFilterEditorModel::TrafficRowGroup::primary,
    TrafficMetricValueKind::duration_us,
};

constexpr std::array<TrafficMetricDescriptor, 10> kTrafficMetricDescriptors {{
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::packet_count,
     "Packets",
     "PacketCount",
     AdvancedFlowFilterEditorModel::TrafficRowGroup::primary,
     TrafficMetricValueKind::count},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::original_bytes,
     "Original bytes",
     "OriginalBytes",
     AdvancedFlowFilterEditorModel::TrafficRowGroup::primary,
     TrafficMetricValueKind::bytes_u64},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::captured_bytes,
     "Captured bytes",
     "CapturedBytes",
     AdvancedFlowFilterEditorModel::TrafficRowGroup::primary,
     TrafficMetricValueKind::bytes_u64},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::max_original_packet_size,
     "Maximum original packet size",
     "MaxOriginalPacketSize",
     AdvancedFlowFilterEditorModel::TrafficRowGroup::additional,
     TrafficMetricValueKind::bytes_u32},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::max_captured_packet_size,
     "Maximum captured packet size",
     "MaxCapturedPacketSize",
     AdvancedFlowFilterEditorModel::TrafficRowGroup::additional,
     TrafficMetricValueKind::bytes_u32},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::fragmented_packet_count,
     "Fragmented packet count",
     "FragmentedPacketCount",
     AdvancedFlowFilterEditorModel::TrafficRowGroup::additional,
     TrafficMetricValueKind::count},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::truncated_packet_count,
     "Truncated packet count",
     "TruncatedPacketCount",
     AdvancedFlowFilterEditorModel::TrafficRowGroup::additional,
     TrafficMetricValueKind::count},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::tcp_syn_count,
     "TCP SYN count",
     "TcpSynCount",
     AdvancedFlowFilterEditorModel::TrafficRowGroup::additional,
     TrafficMetricValueKind::count},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::tcp_fin_count,
     "TCP FIN count",
     "TcpFinCount",
     AdvancedFlowFilterEditorModel::TrafficRowGroup::additional,
     TrafficMetricValueKind::count},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::tcp_rst_count,
     "TCP RST count",
     "TcpRstCount",
     AdvancedFlowFilterEditorModel::TrafficRowGroup::additional,
     TrafficMetricValueKind::count},
}};

constexpr std::array<TrafficMetricDescriptor, 4> kDirectionalTrafficMetricDescriptors {{
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::a_to_b_packets,
     "A -> B packets",
     "AToBPackets",
     AdvancedFlowFilterEditorModel::TrafficRowGroup::directional_packets,
     TrafficMetricValueKind::count},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::b_to_a_packets,
     "B -> A packets",
     "BToAPackets",
     AdvancedFlowFilterEditorModel::TrafficRowGroup::directional_packets,
     TrafficMetricValueKind::count},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::a_to_b_original_bytes,
     "A -> B original bytes",
     "AToBOriginalBytes",
     AdvancedFlowFilterEditorModel::TrafficRowGroup::directional_original_bytes,
     TrafficMetricValueKind::bytes_u64},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::b_to_a_original_bytes,
     "B -> A original bytes",
     "BToAOriginalBytes",
     AdvancedFlowFilterEditorModel::TrafficRowGroup::directional_original_bytes,
     TrafficMetricValueKind::bytes_u64},
}};

template <typename T>
bool contains_advanced_filter_option(const std::vector<T>& values, const T value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}

template <typename T>
bool set_advanced_filter_option_checked(std::vector<T>& values, const T value, const bool checked) {
    if (checked) {
        if (!contains_advanced_filter_option(values, value)) {
            values.push_back(value);
            return true;
        }
        return false;
    }

    const auto original_size = values.size();
    std::erase(values, value);
    return values.size() != original_size;
}

template <typename T, std::size_t N>
QVariantList build_advanced_filter_option_list(
    const std::vector<T>& selected_values,
    const std::array<AdvancedFilterOptionDescriptor<T>, N>& descriptors
) {
    QVariantList options {};
    options.reserve(static_cast<qsizetype>(descriptors.size()));
    for (const auto& descriptor : descriptors) {
        QVariantMap option {};
        option.insert(QStringLiteral("value"), static_cast<int>(descriptor.value));
        option.insert(QStringLiteral("label"), QString::fromLatin1(descriptor.label));
        option.insert(
            QStringLiteral("checked"),
            contains_advanced_filter_option(selected_values, descriptor.value)
        );
        option.insert(
            QStringLiteral("objectNameSuffix"),
            QString::fromLatin1(descriptor.object_name_suffix)
        );
        options.push_back(option);
    }
    return options;
}

template <typename T, std::size_t N>
QVariantList build_advanced_filter_static_option_list(
    const std::array<AdvancedFilterOptionDescriptor<T>, N>& descriptors
) {
    QVariantList options {};
    options.reserve(static_cast<qsizetype>(descriptors.size()));
    for (const auto& descriptor : descriptors) {
        QVariantMap option {};
        option.insert(QStringLiteral("value"), static_cast<int>(descriptor.value));
        option.insert(QStringLiteral("label"), QString::fromLatin1(descriptor.label));
        option.insert(QStringLiteral("objectNameSuffix"), QString::fromLatin1(descriptor.object_name_suffix));
        options.push_back(option);
    }
    return options;
}

std::optional<std::uint32_t> parse_ui_u32_text(const QString& text) {
    const auto trimmed = text.trimmed();
    if (trimmed.isEmpty()) {
        return std::nullopt;
    }

    const auto latin1 = trimmed.toLatin1();
    std::uint32_t value {0U};
    const auto* begin = latin1.constData();
    const auto* end = begin + latin1.size();
    const auto result = std::from_chars(begin, end, value, 10);
    if (result.ec != std::errc {} || result.ptr != end) {
        return std::nullopt;
    }
    return value;
}

std::optional<std::uint64_t> parse_ui_u64_text(const QString& text) {
    const auto trimmed = text.trimmed();
    if (trimmed.isEmpty()) {
        return std::nullopt;
    }

    const auto latin1 = trimmed.toLatin1();
    std::uint64_t value {0U};
    const auto* begin = latin1.constData();
    const auto* end = begin + latin1.size();
    const auto result = std::from_chars(begin, end, value, 10);
    if (result.ec != std::errc {} || result.ptr != end) {
        return std::nullopt;
    }
    return value;
}

template <typename T>
std::optional<T> checked_multiply(const T value, const T multiplier) {
    if (value == 0 || multiplier == 0) {
        return static_cast<T>(0);
    }
    if (value > (std::numeric_limits<T>::max)() / multiplier) {
        return std::nullopt;
    }
    return static_cast<T>(value * multiplier);
}

template <typename T>
std::optional<T> checked_parse_scaled_value(
    const QString& text,
    const std::uint64_t multiplier
) {
    const auto parsed = parse_ui_u64_text(text);
    if (!parsed.has_value()) {
        return std::nullopt;
    }

    const auto scaled = checked_multiply<std::uint64_t>(*parsed, multiplier);
    if (!scaled.has_value() || *scaled > static_cast<std::uint64_t>((std::numeric_limits<T>::max)())) {
        return std::nullopt;
    }
    return static_cast<T>(*scaled);
}

const TrafficMetricDescriptor* traffic_metric_descriptor(
    const AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric metric
) noexcept {
    for (const auto& descriptor : kTrafficMetricDescriptors) {
        if (descriptor.metric == metric) {
            return &descriptor;
        }
    }
    for (const auto& descriptor : kDirectionalTrafficMetricDescriptors) {
        if (descriptor.metric == metric) {
            return &descriptor;
        }
    }
    return nullptr;
}

std::optional<AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric> traffic_metric_from_int(
    const int metric
) {
    const auto converted = static_cast<AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric>(metric);
    return traffic_metric_descriptor(converted) != nullptr ? std::optional {converted} : std::nullopt;
}

std::optional<AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit> traffic_unit_from_int(
    const int unit
) {
    switch (static_cast<AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit>(unit)) {
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::bytes:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::kib:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::mib:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::gib:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::tib:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::microseconds:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::milliseconds:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::seconds:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::minutes:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::hours:
        return static_cast<AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit>(unit);
    default:
        return std::nullopt;
    }
}

std::uint64_t traffic_unit_multiplier(
    const AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit unit
) noexcept {
    switch (unit) {
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::bytes:
        return 1ULL;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::kib:
        return 1024ULL;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::mib:
        return 1024ULL * 1024ULL;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::gib:
        return 1024ULL * 1024ULL * 1024ULL;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::tib:
        return 1024ULL * 1024ULL * 1024ULL * 1024ULL;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::microseconds:
        return 1ULL;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::milliseconds:
        return 1000ULL;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::seconds:
        return 1000ULL * 1000ULL;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::minutes:
        return 60ULL * 1000ULL * 1000ULL;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::hours:
        return 60ULL * 60ULL * 1000ULL * 1000ULL;
    }

    return 1ULL;
}

bool traffic_metric_uses_byte_units(const TrafficMetricDescriptor& descriptor) noexcept {
    return descriptor.value_kind == TrafficMetricValueKind::bytes_u64 ||
        descriptor.value_kind == TrafficMetricValueKind::bytes_u32;
}

bool traffic_metric_uses_packet_size_units(const TrafficMetricDescriptor& descriptor) noexcept {
    return descriptor.value_kind == TrafficMetricValueKind::bytes_u32;
}

bool traffic_metric_uses_duration_units(const TrafficMetricDescriptor& descriptor) noexcept {
    return descriptor.value_kind == TrafficMetricValueKind::duration_us;
}

bool traffic_metric_has_unit_selector(const TrafficMetricDescriptor& descriptor) noexcept {
    return descriptor.value_kind != TrafficMetricValueKind::count;
}

QString traffic_metric_static_unit_text(const TrafficMetricDescriptor& descriptor) {
    return descriptor.value_kind == TrafficMetricValueKind::count ? QStringLiteral("packets") : QString {};
}

QVariantList traffic_metric_unit_options(const TrafficMetricDescriptor& descriptor) {
    if (traffic_metric_uses_packet_size_units(descriptor)) {
        return build_advanced_filter_static_option_list(kAdvancedFlowFilterPacketSizeUnitOptions);
    }
    if (traffic_metric_uses_byte_units(descriptor)) {
        return build_advanced_filter_static_option_list(kAdvancedFlowFilterByteUnitOptions);
    }
    if (traffic_metric_uses_duration_units(descriptor)) {
        return build_advanced_filter_static_option_list(kAdvancedFlowFilterDurationUnitOptions);
    }
    return {};
}

const TimeRangeDescriptor* time_range_descriptor(const QString& metric_id) noexcept {
    for (const auto& descriptor : kTimeRangeDescriptors) {
        if (metric_id == QString::fromLatin1(descriptor.metric_id)) {
            return &descriptor;
        }
    }
    return nullptr;
}

QString traffic_unit_label(
    const TrafficMetricDescriptor& descriptor,
    const AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit unit
) {
    const auto options = traffic_metric_unit_options(descriptor);
    for (const auto& option : options) {
        const auto map = option.toMap();
        if (map.value(QStringLiteral("value")).toInt() == static_cast<int>(unit)) {
            return map.value(QStringLiteral("label")).toString();
        }
    }
    return {};
}

bool traffic_unit_allowed_for_metric(
    const TrafficMetricDescriptor& descriptor,
    const AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit unit
) noexcept {
    const auto options = traffic_metric_unit_options(descriptor);
    for (const auto& option : options) {
        if (option.toMap().value(QStringLiteral("value")).toInt() == static_cast<int>(unit)) {
            return true;
        }
    }
    return false;
}

AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit traffic_metric_default_empty_unit(
    const TrafficMetricDescriptor& descriptor
) noexcept {
    using TrafficMetric = AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric;
    using TrafficUnit = AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit;

    if (descriptor.value_kind == TrafficMetricValueKind::duration_us) {
        return TrafficUnit::seconds;
    }

    switch (descriptor.metric) {
    case TrafficMetric::original_bytes:
    case TrafficMetric::captured_bytes:
    case TrafficMetric::a_to_b_original_bytes:
    case TrafficMetric::b_to_a_original_bytes:
        return TrafficUnit::kib;
    case TrafficMetric::max_original_packet_size:
    case TrafficMetric::max_captured_packet_size:
        return TrafficUnit::bytes;
    case TrafficMetric::packet_count:
    case TrafficMetric::a_to_b_packets:
    case TrafficMetric::b_to_a_packets:
    case TrafficMetric::fragmented_packet_count:
    case TrafficMetric::truncated_packet_count:
    case TrafficMetric::tcp_syn_count:
    case TrafficMetric::tcp_fin_count:
    case TrafficMetric::tcp_rst_count:
        return TrafficUnit::bytes;
    }

    return TrafficUnit::bytes;
}

std::optional<std::uint64_t> exact_scaled_value_for_text(
    const QString& text,
    const AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit unit
) {
    return checked_parse_scaled_value<std::uint64_t>(text, traffic_unit_multiplier(unit));
}

AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit choose_largest_exact_unit(
    const TrafficMetricDescriptor& descriptor,
    const std::optional<std::uint64_t> minimum,
    const std::optional<std::uint64_t> maximum
) {
    if (!traffic_metric_has_unit_selector(descriptor)) {
        return AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::bytes;
    }

    if (!minimum.has_value() && !maximum.has_value()) {
        return traffic_metric_default_empty_unit(descriptor);
    }

    const auto choose_from = [&](const auto& options) {
        for (auto it = options.rbegin(); it != options.rend(); ++it) {
            const auto multiplier = traffic_unit_multiplier(it->value);
            const auto exact_for_min = !minimum.has_value() || (*minimum % multiplier == 0U);
            const auto exact_for_max = !maximum.has_value() || (*maximum % multiplier == 0U);
            if (exact_for_min && exact_for_max) {
                return it->value;
            }
        }
        return options.front().value;
    };

    if (traffic_metric_uses_packet_size_units(descriptor)) {
        return choose_from(kAdvancedFlowFilterPacketSizeUnitOptions);
    }
    if (traffic_metric_uses_byte_units(descriptor)) {
        return choose_from(kAdvancedFlowFilterByteUnitOptions);
    }
    return choose_from(kAdvancedFlowFilterDurationUnitOptions);
}

QString format_scaled_integer_text(
    const std::optional<std::uint64_t> value,
    const AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit unit
) {
    if (!value.has_value()) {
        return {};
    }
    const auto multiplier = traffic_unit_multiplier(unit);
    return multiplier == 0U ? QString {} : QString::number(*value / multiplier);
}

std::optional<session_detail::AdvancedFlowFilterInclusiveRange<std::uint64_t>> load_u64_range(
    const std::optional<session_detail::AdvancedFlowFilterInclusiveRange<std::uint64_t>>& range
) {
    return range;
}

std::optional<session_detail::AdvancedFlowFilterInclusiveRange<std::uint64_t>> promote_u32_range(
    const std::optional<session_detail::AdvancedFlowFilterInclusiveRange<std::uint32_t>>& range
) {
    if (!range.has_value()) {
        return std::nullopt;
    }
    return session_detail::AdvancedFlowFilterInclusiveRange<std::uint64_t> {
        .min = range->min.has_value() ? std::optional<std::uint64_t> {*range->min} : std::nullopt,
        .max = range->max.has_value() ? std::optional<std::uint64_t> {*range->max} : std::nullopt,
    };
}

std::optional<session_detail::AdvancedFlowFilterInclusiveRange<std::uint64_t>> traffic_metric_range_u64(
    const session_detail::AdvancedFlowFilterAggregateCriteria& aggregate,
    const AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric metric
) {
    using Metric = AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric;
    switch (metric) {
    case Metric::packet_count:
        return load_u64_range(aggregate.packet_count);
    case Metric::original_bytes:
        return load_u64_range(aggregate.original_bytes);
    case Metric::captured_bytes:
        return load_u64_range(aggregate.captured_bytes);
    case Metric::a_to_b_packets:
        return load_u64_range(aggregate.a_to_b_packet_count);
    case Metric::b_to_a_packets:
        return load_u64_range(aggregate.b_to_a_packet_count);
    case Metric::a_to_b_original_bytes:
        return load_u64_range(aggregate.a_to_b_original_bytes);
    case Metric::b_to_a_original_bytes:
        return load_u64_range(aggregate.b_to_a_original_bytes);
    case Metric::max_original_packet_size:
        return promote_u32_range(aggregate.max_original_packet_length);
    case Metric::max_captured_packet_size:
        return promote_u32_range(aggregate.max_captured_packet_length);
    case Metric::fragmented_packet_count:
        return load_u64_range(aggregate.fragmented_packet_count);
    case Metric::truncated_packet_count:
        return load_u64_range(aggregate.truncated_packet_count);
    case Metric::tcp_syn_count:
        return load_u64_range(aggregate.tcp_syn_count);
    case Metric::tcp_fin_count:
        return load_u64_range(aggregate.tcp_fin_count);
    case Metric::tcp_rst_count:
        return load_u64_range(aggregate.tcp_rst_count);
    }

    return std::nullopt;
}

std::optional<session_detail::AdvancedFlowFilterInclusiveRange<std::uint64_t>> time_range_u64(
    const session_detail::AdvancedFlowFilterTimeCriteria& time,
    const QString& metric_id
) {
    if (metric_id == QStringLiteral("start")) {
        return load_u64_range(time.start_us);
    }
    if (metric_id == QStringLiteral("end")) {
        return load_u64_range(time.end_us);
    }
    if (metric_id == QStringLiteral("overlap")) {
        return load_u64_range(time.overlap_us);
    }
    return std::nullopt;
}

bool any_additional_traffic_metric_active(const session_detail::AdvancedFlowFilterAggregateCriteria& aggregate) {
    for (const auto& descriptor : kTrafficMetricDescriptors) {
        if (descriptor.group != AdvancedFlowFilterEditorModel::TrafficRowGroup::additional) {
            continue;
        }
        if (traffic_metric_range_u64(aggregate, descriptor.metric).has_value()) {
            return true;
        }
    }
    return false;
}

bool service_kind_is_state(const session_detail::AdvancedFlowFilterServicePredicateKind kind) noexcept {
    return kind == session_detail::AdvancedFlowFilterServicePredicateKind::known ||
        kind == session_detail::AdvancedFlowFilterServicePredicateKind::unknown;
}

bool service_text_rules_disabled_for_include_state(const bool include_known, const bool include_unknown) noexcept {
    return include_unknown && !include_known;
}

QString formatIpv4Address(const std::uint32_t address) {
    return QHostAddress(address).toString();
}

QString formatIpv6Address(const std::array<std::uint8_t, 16>& address) {
    Q_IPV6ADDR qt_address {};
    for (std::size_t index = 0; index < address.size(); ++index) {
        qt_address[static_cast<int>(index)] = address[index];
    }
    return QHostAddress(qt_address).toString();
}

std::size_t count_range_atomic_rules(
    const std::optional<session_detail::AdvancedFlowFilterInclusiveRange<std::uint64_t>>& range
) noexcept {
    return (range.has_value() && range->min.has_value() ? 1U : 0U) +
        (range.has_value() && range->max.has_value() ? 1U : 0U);
}

std::size_t count_range_atomic_rules(
    const std::optional<session_detail::AdvancedFlowFilterInclusiveRange<std::uint32_t>>& range
) noexcept {
    return (range.has_value() && range->min.has_value() ? 1U : 0U) +
        (range.has_value() && range->max.has_value() ? 1U : 0U);
}

std::size_t count_aggregate_atomic_rules(
    const session_detail::AdvancedFlowFilterAggregateCriteria& aggregate
) noexcept {
    return aggregate.packet_distribution.include.size() +
        aggregate.packet_distribution.exclude.size() +
        aggregate.data_distribution.include.size() +
        aggregate.data_distribution.exclude.size() +
        count_range_atomic_rules(aggregate.packet_count) +
        count_range_atomic_rules(aggregate.original_bytes) +
        count_range_atomic_rules(aggregate.captured_bytes) +
        count_range_atomic_rules(aggregate.a_to_b_packet_count) +
        count_range_atomic_rules(aggregate.b_to_a_packet_count) +
        count_range_atomic_rules(aggregate.a_to_b_original_bytes) +
        count_range_atomic_rules(aggregate.b_to_a_original_bytes) +
        count_range_atomic_rules(aggregate.fragmented_packet_count) +
        count_range_atomic_rules(aggregate.truncated_packet_count) +
        count_range_atomic_rules(aggregate.tcp_syn_count) +
        count_range_atomic_rules(aggregate.tcp_fin_count) +
        count_range_atomic_rules(aggregate.tcp_rst_count) +
        count_range_atomic_rules(aggregate.max_original_packet_length) +
        count_range_atomic_rules(aggregate.max_captured_packet_length);
}

std::size_t count_time_atomic_rules(
    const session_detail::AdvancedFlowFilterTimeCriteria& time
) noexcept {
    return count_range_atomic_rules(time.start_us) +
        count_range_atomic_rules(time.end_us) +
        count_range_atomic_rules(time.overlap_us) +
        count_range_atomic_rules(time.duration_us);
}

std::array<std::uint8_t, 16> qhost_to_ipv6_bytes(const QHostAddress& address) {
    const auto ipv6 = address.toIPv6Address();
    std::array<std::uint8_t, 16> bytes {};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = ipv6[static_cast<int>(index)];
    }
    return bytes;
}

std::vector<LayerKey> protocol_path_layers_from_predicate(
    const std::vector<session_detail::AdvancedFlowFilterProtocolLayerPredicate>& layers
) {
    std::vector<LayerKey> converted {};
    converted.reserve(layers.size());
    for (const auto& layer : layers) {
        converted.push_back(LayerKey {
            .kind = layer.kind,
            .identifier = layer.identifier.value_or(ProtocolLayerIdentifier {}),
        });
    }
    return converted;
}

bool protocol_path_predicate_is_ui_managed(
    const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate
) noexcept {
    return predicate.match_kind == session_detail::AdvancedFlowFilterProtocolPathMatchKind::exact_path ||
        predicate.match_kind == session_detail::AdvancedFlowFilterProtocolPathMatchKind::path_prefix;
}

ProtocolPathStatisticsMode protocol_path_selector_mode_from_predicate(
    const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate
) noexcept {
    if (predicate.match_kind == session_detail::AdvancedFlowFilterProtocolPathMatchKind::exact_path) {
        return ProtocolPathStatisticsMode::terminal_paths;
    }

    return std::any_of(predicate.layers.begin(), predicate.layers.end(), [](const auto& layer) {
               return layer.identifier.has_value() &&
                   layer.identifier->kind != ProtocolLayerIdentifierKind::none;
           })
        ? ProtocolPathStatisticsMode::identity_tree
        : ProtocolPathStatisticsMode::kind_overview;
}

QString protocol_path_selector_mode_label(const ProtocolPathStatisticsMode mode) {
    switch (mode) {
    case ProtocolPathStatisticsMode::kind_overview:
        return QStringLiteral("Kind");
    case ProtocolPathStatisticsMode::identity_tree:
        return QStringLiteral("Identity");
    case ProtocolPathStatisticsMode::terminal_paths:
        return QStringLiteral("Terminal");
    }

    return QStringLiteral("Path");
}

QString protocol_path_compact_display_text(
    const std::vector<session_detail::AdvancedFlowFilterProtocolLayerPredicate>& layers
) {
    const auto converted_layers = protocol_path_layers_from_predicate(layers);
    const ProtocolPath path {converted_layers};
    return QString::fromStdString(session_detail::format_protocol_path_compact_display_text(path));
}

QString protocol_path_full_display_text(
    const std::vector<session_detail::AdvancedFlowFilterProtocolLayerPredicate>& layers
) {
    const auto converted_layers = protocol_path_layers_from_predicate(layers);
    const ProtocolPath path {converted_layers};
    return QString::fromStdString(session_detail::build_protocol_path_presentation(&path).full_text);
}

ProtocolLayerKind default_contains_layer_kind() noexcept {
    const auto descriptors = session_detail::protocol_path_contains_layer_descriptors();
    return descriptors.empty() ? ProtocolLayerKind::unknown : descriptors.front().kind;
}

std::optional<AdvancedFlowFilterEditorModel::AdvancedFlowFilterContainsLayerIdentifierMode>
contains_layer_identifier_mode_from_int(const int mode) {
    switch (static_cast<AdvancedFlowFilterEditorModel::AdvancedFlowFilterContainsLayerIdentifierMode>(mode)) {
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterContainsLayerIdentifierMode::any:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterContainsLayerIdentifierMode::exact:
        return static_cast<AdvancedFlowFilterEditorModel::AdvancedFlowFilterContainsLayerIdentifierMode>(mode);
    }

    return std::nullopt;
}

std::optional<ProtocolLayerKind> contains_layer_kind_from_int(const int kind) {
    const auto converted = static_cast<ProtocolLayerKind>(kind);
    return session_detail::protocol_path_contains_layer_descriptor(converted) != nullptr
        ? std::optional<ProtocolLayerKind> {converted}
        : std::nullopt;
}

QVariantList build_contains_layer_option_list() {
    QVariantList options {};
    const auto descriptors = session_detail::protocol_path_contains_layer_descriptors();
    options.reserve(static_cast<qsizetype>(descriptors.size()));
    for (const auto& descriptor : descriptors) {
        QVariantMap option {};
        option.insert(QStringLiteral("value"), static_cast<int>(descriptor.kind));
        option.insert(QStringLiteral("label"), QString::fromLatin1(descriptor.layer_label));
        option.insert(QStringLiteral("objectNameSuffix"), QString::fromLatin1(descriptor.object_name_suffix));
        option.insert(QStringLiteral("identifierLabel"), QString::fromLatin1(descriptor.identifier_label));
        option.insert(
            QStringLiteral("preferredInputFormat"),
            static_cast<int>(descriptor.preferred_input_format)
        );
        options.push_back(option);
    }
    return options;
}

QString contains_layer_exact_placeholder_text(const session_detail::ProtocolPathContainsLayerDescriptor& descriptor) {
    switch (descriptor.preferred_input_format) {
    case session_detail::ProtocolPathIdentifierInputFormat::decimal:
        return descriptor.max_value > 9999U ? QStringLiteral("200") : QStringLiteral("413");
    case session_detail::ProtocolPathIdentifierInputFormat::hexadecimal:
        return descriptor.max_value <= 0xFFFFFFU
            ? QStringLiteral("0x123456")
            : QStringLiteral("0x12345678");
    }

    return {};
}

QString contains_layer_compact_text(
    const session_detail::ProtocolPathContainsLayerDescriptor& descriptor,
    const AdvancedFlowFilterEditorModel::AdvancedFlowFilterContainsLayerIdentifierMode mode,
    const QString& exact_value_text
) {
    if (mode == AdvancedFlowFilterEditorModel::AdvancedFlowFilterContainsLayerIdentifierMode::any) {
        return QStringLiteral("%1 / Any").arg(QString::fromLatin1(descriptor.layer_label));
    }

    const auto trimmed = exact_value_text.trimmed();
    if (trimmed.isEmpty()) {
        return QStringLiteral("%1 / %2").arg(
            QString::fromLatin1(descriptor.layer_label),
            QString::fromLatin1(descriptor.identifier_label)
        );
    }

    return QStringLiteral("%1 / %2 %3").arg(
        QString::fromLatin1(descriptor.layer_label),
        QString::fromLatin1(descriptor.identifier_label),
        trimmed
    );
}

bool contains_layer_predicate_is_ui_managed(
    const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate
) noexcept {
    return predicate.match_kind == session_detail::AdvancedFlowFilterProtocolPathMatchKind::contains_layer;
}

std::optional<session_detail::AdvancedFlowFilterProtocolPathPredicate> contains_layer_predicate_from_editor_row(
    const auto& row,
    QString* error_text,
    const QString& row_label
) {
    const auto* descriptor = session_detail::protocol_path_contains_layer_descriptor(row.kind);
    if (descriptor == nullptr) {
        if (error_text != nullptr) {
            *error_text = QStringLiteral("%1: Layer kind is unsupported.").arg(row_label);
        }
        return std::nullopt;
    }

    session_detail::AdvancedFlowFilterProtocolLayerPredicate layer {
        .kind = descriptor->kind,
        .identifier = std::nullopt,
    };
    if (row.identifier_mode == AdvancedFlowFilterEditorModel::AdvancedFlowFilterContainsLayerIdentifierMode::exact) {
        const auto trimmed = row.exact_value_text.trimmed();
        if (trimmed.isEmpty()) {
            if (error_text != nullptr) {
                *error_text = QStringLiteral("%1: %2 value is required for Exact mode.")
                    .arg(row_label, QString::fromLatin1(descriptor->identifier_label));
            }
            return std::nullopt;
        }

        const auto parsed = session_detail::parse_advanced_flow_filter_unsigned_integer_text(trimmed.toStdString());
        if (!parsed.ok) {
            if (error_text != nullptr) {
                *error_text = parsed.overflow
                    ? QStringLiteral("%1: %2 value is too large.")
                          .arg(row_label, QString::fromLatin1(descriptor->identifier_label))
                    : QStringLiteral("%1: %2 value must be a valid integer.")
                          .arg(row_label, QString::fromLatin1(descriptor->identifier_label));
            }
            return std::nullopt;
        }
        if (parsed.value > descriptor->max_value) {
            if (error_text != nullptr) {
                *error_text = QStringLiteral("%1: %2 value is out of range.")
                    .arg(row_label, QString::fromLatin1(descriptor->identifier_label));
            }
            return std::nullopt;
        }

        layer.identifier = ProtocolLayerIdentifier {
            .kind = descriptor->identifier_kind,
            .value = parsed.value,
        };
    }

    return session_detail::AdvancedFlowFilterProtocolPathPredicate {
        .match_kind = session_detail::AdvancedFlowFilterProtocolPathMatchKind::contains_layer,
        .layers = {std::move(layer)},
    };
}

std::optional<bool> contains_layer_row_applicability(
    const auto& row,
    const std::function<std::optional<bool>(const session_detail::AdvancedFlowFilterProtocolPathPredicate&)>& resolver,
    bool* predicate_valid = nullptr
) {
    QString ignored_error {};
    const auto predicate = contains_layer_predicate_from_editor_row(row, &ignored_error, QStringLiteral("Contains Layer"));
    if (predicate_valid != nullptr) {
        *predicate_valid = predicate.has_value();
    }
    if (!predicate.has_value()) {
        return std::nullopt;
    }
    return resolver ? resolver(*predicate) : std::nullopt;
}

std::optional<AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection> advanced_flow_filter_section_from_int(
    const int section
) {
    switch (static_cast<AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection>(section)) {
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::address_family:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::flow_protocol:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::detected_protocol:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::tls_version:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::quic_version:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::directionality:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::ports:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::ip_addresses:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::time:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::traffic:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::service:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::protocol_path:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::contains_layer:
        return static_cast<AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection>(section);
    default:
        return std::nullopt;
    }
}

bool advanced_flow_filter_section_enabled(
    const session_detail::AdvancedFlowFilterDocumentSectionStates& states,
    const AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection section
) noexcept {
    switch (section) {
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::address_family:
        return states.address_family;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::flow_protocol:
        return states.flow_protocol;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::detected_protocol:
        return states.detected_protocol;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::tls_version:
        return states.tls_version;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::quic_version:
        return states.quic_version;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::directionality:
        return states.directionality;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::ports:
        return states.ports;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::ip_addresses:
        return states.ip_addresses;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::time:
        return states.time;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::traffic:
        return states.traffic;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::service:
        return states.service;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::protocol_path:
        return states.protocol_path;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::contains_layer:
        return states.contains_layer;
    }

    return false;
}

bool* advanced_flow_filter_section_enabled_mutable(
    session_detail::AdvancedFlowFilterDocumentSectionStates& states,
    const AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection section
) noexcept {
    switch (section) {
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::address_family:
        return &states.address_family;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::flow_protocol:
        return &states.flow_protocol;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::detected_protocol:
        return &states.detected_protocol;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::tls_version:
        return &states.tls_version;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::quic_version:
        return &states.quic_version;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::directionality:
        return &states.directionality;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::ports:
        return &states.ports;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::ip_addresses:
        return &states.ip_addresses;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::time:
        return &states.time;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::traffic:
        return &states.traffic;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::service:
        return &states.service;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::protocol_path:
        return &states.protocol_path;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::contains_layer:
        return &states.contains_layer;
    }

    return nullptr;
}

std::size_t count_configured_port_rows(const auto& rows) {
    std::size_t count {0};
    for (const auto& row : rows) {
        const auto primary = row.primary_text.trimmed();
        const auto secondary = row.secondary_text.trimmed();
        if (!row.range_enabled) {
            const auto port = parse_ui_u32_text(primary);
            if (port.has_value() && *port <= 65535U) {
                ++count;
            }
            continue;
        }

        if (primary.isEmpty() || secondary.isEmpty()) {
            continue;
        }

        const auto first = parse_ui_u32_text(primary);
        const auto last = parse_ui_u32_text(secondary);
        if (first.has_value() && last.has_value() && *first <= 65535U && *last <= 65535U && *first <= *last) {
            ++count;
        }
    }
    return count;
}

std::size_t count_configured_address_rows(const auto& rows) {
    std::size_t count {0};
    for (const auto& row : rows) {
        const auto address_text = row.address_text.trimmed();
        const auto prefix_text = row.prefix_text.trimmed();
        if (address_text.isEmpty()) {
            continue;
        }

        QHostAddress address {};
        if (!address.setAddress(address_text)) {
            continue;
        }

        const auto protocol = address.protocol();
        if (protocol != QAbstractSocket::IPv4Protocol && protocol != QAbstractSocket::IPv6Protocol) {
            continue;
        }

        if (!row.subnet_enabled) {
            ++count;
            continue;
        }

        const auto prefix = parse_ui_u32_text(prefix_text);
        if (!prefix.has_value()) {
            continue;
        }

        if ((protocol == QAbstractSocket::IPv4Protocol && *prefix <= 32U) ||
            (protocol == QAbstractSocket::IPv6Protocol && *prefix <= 128U)) {
            ++count;
        }
    }
    return count;
}

std::size_t count_configured_traffic_rows(const auto& rows, const auto& descriptors) {
    std::size_t count {0};
    for (const auto& descriptor : descriptors) {
        const auto index = static_cast<std::size_t>(descriptor.metric);
        if (index >= rows.size()) {
            continue;
        }

        const auto minimum_text = rows[index].min_text.trimmed();
        const auto maximum_text = rows[index].max_text.trimmed();
        if (minimum_text.isEmpty() && maximum_text.isEmpty()) {
            continue;
        }

        const auto multiplier = traffic_metric_has_unit_selector(descriptor)
            ? traffic_unit_multiplier(rows[index].unit)
            : 1ULL;
        const auto uses_u32_storage = descriptor.value_kind == TrafficMetricValueKind::bytes_u32;
        const auto min_valid = minimum_text.isEmpty() ||
            (uses_u32_storage
                ? checked_parse_scaled_value<std::uint32_t>(minimum_text, multiplier).has_value()
                : checked_parse_scaled_value<std::uint64_t>(minimum_text, multiplier).has_value());
        const auto max_valid = maximum_text.isEmpty() ||
            (uses_u32_storage
                ? checked_parse_scaled_value<std::uint32_t>(maximum_text, multiplier).has_value()
                : checked_parse_scaled_value<std::uint64_t>(maximum_text, multiplier).has_value());
        if (!min_valid || !max_valid) {
            continue;
        }

        if (uses_u32_storage) {
            const auto parsed_min = minimum_text.isEmpty()
                ? std::optional<std::uint32_t> {}
                : checked_parse_scaled_value<std::uint32_t>(minimum_text, multiplier);
            const auto parsed_max = maximum_text.isEmpty()
                ? std::optional<std::uint32_t> {}
                : checked_parse_scaled_value<std::uint32_t>(maximum_text, multiplier);
            if (parsed_min.has_value() && parsed_max.has_value() && *parsed_min > *parsed_max) {
                continue;
            }
        } else {
            const auto parsed_min = minimum_text.isEmpty()
                ? std::optional<std::uint64_t> {}
                : checked_parse_scaled_value<std::uint64_t>(minimum_text, multiplier);
            const auto parsed_max = maximum_text.isEmpty()
                ? std::optional<std::uint64_t> {}
                : checked_parse_scaled_value<std::uint64_t>(maximum_text, multiplier);
            if (parsed_min.has_value() && parsed_max.has_value() && *parsed_min > *parsed_max) {
                continue;
            }
        }

        count += minimum_text.isEmpty() ? 0U : 1U;
        count += maximum_text.isEmpty() ? 0U : 1U;
    }
    return count;
}

std::size_t count_configured_time_range_rows(const auto& rows) {
    std::size_t count {0};
    for (std::size_t index = 0; index < rows.size() && index < kTimeRangeDescriptors.size(); ++index) {
        const auto& row = rows[index];
        const auto from_text = row.from_text.trimmed();
        const auto to_text = row.to_text.trimmed();
        if (from_text.isEmpty() && to_text.isEmpty()) {
            continue;
        }

        const auto parsed_from = from_text.isEmpty()
            ? session_detail::AdvancedFlowFilterParsedUtcTimestampText {.ok = true}
            : session_detail::parse_advanced_flow_filter_utc_timestamp_text(from_text.toStdString());
        const auto parsed_to = to_text.isEmpty()
            ? session_detail::AdvancedFlowFilterParsedUtcTimestampText {.ok = true}
            : session_detail::parse_advanced_flow_filter_utc_timestamp_text(to_text.toStdString());
        if (!parsed_from.ok || !parsed_to.ok) {
            continue;
        }
        if (!from_text.isEmpty() && !to_text.isEmpty() && parsed_from.value_us > parsed_to.value_us) {
            continue;
        }

        count += static_cast<std::size_t>(!from_text.isEmpty()) + static_cast<std::size_t>(!to_text.isEmpty());
    }
    return count;
}

std::size_t count_configured_single_traffic_row(const auto& row, const TrafficMetricDescriptor& descriptor) {
    const auto minimum_text = row.min_text.trimmed();
    const auto maximum_text = row.max_text.trimmed();
    if (minimum_text.isEmpty() && maximum_text.isEmpty()) {
        return 0U;
    }

    const auto multiplier = traffic_metric_has_unit_selector(descriptor)
        ? traffic_unit_multiplier(row.unit)
        : 1ULL;
    const auto uses_u32_storage = descriptor.value_kind == TrafficMetricValueKind::bytes_u32;
    const auto min_valid = minimum_text.isEmpty() ||
        (uses_u32_storage
            ? checked_parse_scaled_value<std::uint32_t>(minimum_text, multiplier).has_value()
            : checked_parse_scaled_value<std::uint64_t>(minimum_text, multiplier).has_value());
    const auto max_valid = maximum_text.isEmpty() ||
        (uses_u32_storage
            ? checked_parse_scaled_value<std::uint32_t>(maximum_text, multiplier).has_value()
            : checked_parse_scaled_value<std::uint64_t>(maximum_text, multiplier).has_value());
    if (!min_valid || !max_valid) {
        return 0U;
    }

    if (uses_u32_storage) {
        const auto parsed_min = minimum_text.isEmpty()
            ? std::optional<std::uint32_t> {}
            : checked_parse_scaled_value<std::uint32_t>(minimum_text, multiplier);
        const auto parsed_max = maximum_text.isEmpty()
            ? std::optional<std::uint32_t> {}
            : checked_parse_scaled_value<std::uint32_t>(maximum_text, multiplier);
        if (parsed_min.has_value() && parsed_max.has_value() && *parsed_min > *parsed_max) {
            return 0U;
        }
    } else {
        const auto parsed_min = minimum_text.isEmpty()
            ? std::optional<std::uint64_t> {}
            : checked_parse_scaled_value<std::uint64_t>(minimum_text, multiplier);
        const auto parsed_max = maximum_text.isEmpty()
            ? std::optional<std::uint64_t> {}
            : checked_parse_scaled_value<std::uint64_t>(maximum_text, multiplier);
        if (parsed_min.has_value() && parsed_max.has_value() && *parsed_min > *parsed_max) {
            return 0U;
        }
    }

    return static_cast<std::size_t>(!minimum_text.isEmpty()) + static_cast<std::size_t>(!maximum_text.isEmpty());
}

std::size_t count_configured_service_rows(const auto& rows) {
    return static_cast<std::size_t>(std::count_if(
        rows.begin(),
        rows.end(),
        [](const auto& row) { return !row.text.trimmed().isEmpty(); }
    ));
}

std::size_t count_configured_contains_layer_rows(const auto& rows) {
    std::size_t count {0};
    for (const auto& row : rows) {
        if (contains_layer_predicate_from_editor_row(row, nullptr, QStringLiteral("Contains Layer")).has_value()) {
            ++count;
        }
    }
    return count;
}

QString format_section_summary_text(const std::size_t configured_rule_count, const bool enabled) {
    if (configured_rule_count == 0U) {
        return enabled ? QString {} : QStringLiteral("Disabled");
    }

    const auto rule_text = QStringLiteral("%1 %2")
        .arg(QString::number(configured_rule_count))
        .arg(configured_rule_count == 1U ? QStringLiteral("rule") : QStringLiteral("rules"));
    return enabled ? rule_text : QStringLiteral("%1 · Disabled").arg(rule_text);
}

}  // namespace

AdvancedFlowFilterEditorModel::AdvancedFlowFilterEditorModel(
    session_detail::AdvancedFlowFilterDocumentState& document_state,
    QObject* parent
)
    : QObject(parent)
    , document_state_(document_state) {}

int AdvancedFlowFilterEditorModel::revision() const noexcept {
    return revision_;
}

int AdvancedFlowFilterEditorModel::sectionSummaryRevision() const noexcept {
    return section_summary_revision_;
}

int AdvancedFlowFilterEditorModel::documentReloadRevision() const noexcept {
    return document_reload_revision_;
}

QString AdvancedFlowFilterEditorModel::validationText() const {
    return validation_text_;
}

bool AdvancedFlowFilterEditorModel::draftClearUnsavedChangesAvailable() const noexcept {
    return document_state_.saved_baseline() != nullptr &&
        (document_state_.can_clear_unsaved_changes() || has_unsynchronized_buffered_changes_);
}

bool AdvancedFlowFilterEditorModel::draftClearAllAvailable() const noexcept {
    return has_unsynchronized_buffered_changes_ ||
        !is_default_advanced_flow_filter_document(document_state_.current_user_visible_document());
}

bool AdvancedFlowFilterEditorModel::hasUnsynchronizedBufferedChanges() const noexcept {
    return has_unsynchronized_buffered_changes_;
}

bool AdvancedFlowFilterEditorModel::sectionEnabled(const int section) const noexcept {
    const auto parsed_section = advanced_flow_filter_section_from_int(section);
    if (!parsed_section.has_value()) {
        return false;
    }

    return advanced_flow_filter_section_enabled(
        document_state_.current_user_visible_document().section_states,
        *parsed_section
    );
}

bool AdvancedFlowFilterEditorModel::sectionHasConfiguredPredicates(const int section) const noexcept {
    return sectionConfiguredRuleCount(section) > 0;
}

bool AdvancedFlowFilterEditorModel::sectionHasExclusions(const int section) const noexcept {
    const auto parsed_section = advanced_flow_filter_section_from_int(section);
    if (!parsed_section.has_value()) {
        return false;
    }

    const auto& spec = document_state_.current_user_visible_document().configured_spec;
    switch (*parsed_section) {
    case AdvancedFlowFilterFiniteSection::address_family:
        return !spec.address_family.exclude.empty();
    case AdvancedFlowFilterFiniteSection::flow_protocol:
        return !spec.flow_protocol.exclude.empty();
    case AdvancedFlowFilterFiniteSection::detected_protocol:
        return !spec.detected_protocol.exclude.empty();
    case AdvancedFlowFilterFiniteSection::tls_version:
        return !spec.tls_version.exclude.empty();
    case AdvancedFlowFilterFiniteSection::quic_version:
        return !spec.quic_version.exclude.empty();
    case AdvancedFlowFilterFiniteSection::directionality:
        return !spec.directionality.exclude.empty();
    case AdvancedFlowFilterFiniteSection::ports:
        return document_state_.is_editing()
            ? !port_exclude_rows_.empty()
            : !spec.ports.exclude.empty();
    case AdvancedFlowFilterFiniteSection::ip_addresses:
        return document_state_.is_editing()
            ? !address_exclude_rows_.empty()
            : (!spec.addresses.ipv4_exclude.empty() || !spec.addresses.ipv6_exclude.empty());
    case AdvancedFlowFilterFiniteSection::time:
    case AdvancedFlowFilterFiniteSection::traffic:
        return false;
    case AdvancedFlowFilterFiniteSection::service:
        if (document_state_.is_editing()) {
            return service_exclude_known_ || service_exclude_unknown_ || !service_exclude_text_rows_.empty();
        }
        return std::any_of(
            spec.service.exclude.begin(),
            spec.service.exclude.end(),
            [](const auto&) { return true; });
    case AdvancedFlowFilterFiniteSection::protocol_path:
        return document_state_.is_editing()
            ? !protocol_path_exclude_rows_.empty()
            : std::any_of(
                  spec.protocol_path.exclude.begin(),
                  spec.protocol_path.exclude.end(),
                  [](const auto& predicate) {
                      return protocol_path_predicate_is_ui_managed(predicate);
                  });
    case AdvancedFlowFilterFiniteSection::contains_layer:
        return document_state_.is_editing()
            ? !contains_layer_exclude_rows_.empty()
            : std::any_of(
                  spec.protocol_path.exclude.begin(),
                  spec.protocol_path.exclude.end(),
                  [](const auto& predicate) {
                      return contains_layer_predicate_is_ui_managed(predicate);
                  });
    }

    return false;
}

int AdvancedFlowFilterEditorModel::sectionConfiguredRuleCount(const int section) const noexcept {
    const auto parsed_section = advanced_flow_filter_section_from_int(section);
    if (!parsed_section.has_value()) {
        return 0;
    }

    const auto& document = document_state_.current_user_visible_document();
    const auto& spec = document.configured_spec;
    std::size_t count {0};

    switch (*parsed_section) {
    case AdvancedFlowFilterFiniteSection::address_family:
        count = spec.address_family.include.size() + spec.address_family.exclude.size();
        break;
    case AdvancedFlowFilterFiniteSection::flow_protocol:
        count = spec.flow_protocol.include.size() + spec.flow_protocol.exclude.size();
        break;
    case AdvancedFlowFilterFiniteSection::detected_protocol:
        count = spec.detected_protocol.include.size() + spec.detected_protocol.exclude.size();
        break;
    case AdvancedFlowFilterFiniteSection::tls_version:
        count = spec.tls_version.include.size() + spec.tls_version.exclude.size();
        break;
    case AdvancedFlowFilterFiniteSection::quic_version:
        count = spec.quic_version.include.size() + spec.quic_version.exclude.size();
        break;
    case AdvancedFlowFilterFiniteSection::directionality:
        count = spec.directionality.include.size() + spec.directionality.exclude.size();
        break;
    case AdvancedFlowFilterFiniteSection::ports:
        count = document_state_.is_editing()
            ? count_configured_port_rows(port_include_rows_) + count_configured_port_rows(port_exclude_rows_)
            : spec.ports.include.size() + spec.ports.exclude.size();
        break;
    case AdvancedFlowFilterFiniteSection::ip_addresses:
        count = document_state_.is_editing()
            ? count_configured_address_rows(address_include_rows_) + count_configured_address_rows(address_exclude_rows_)
            : spec.addresses.ipv4_include.size() + spec.addresses.ipv4_exclude.size() +
                spec.addresses.ipv6_include.size() + spec.addresses.ipv6_exclude.size();
        break;
    case AdvancedFlowFilterFiniteSection::time:
        count = document_state_.is_editing()
            ? count_configured_time_range_rows(time_range_rows_) + count_configured_single_traffic_row(time_duration_row_, kTimeDurationDescriptor)
            : count_time_atomic_rules(spec.time);
        break;
    case AdvancedFlowFilterFiniteSection::traffic:
        count = document_state_.is_editing()
            ? spec.aggregate.packet_distribution.include.size() +
                spec.aggregate.packet_distribution.exclude.size() +
                spec.aggregate.data_distribution.include.size() +
                spec.aggregate.data_distribution.exclude.size() +
                count_configured_traffic_rows(traffic_rows_, kTrafficMetricDescriptors) +
                count_configured_traffic_rows(traffic_rows_, kDirectionalTrafficMetricDescriptors)
            : count_aggregate_atomic_rules(spec.aggregate);
        break;
    case AdvancedFlowFilterFiniteSection::service:
        count = document_state_.is_editing()
            ? (service_include_known_ ? 1U : 0U) + (service_include_unknown_ ? 1U : 0U) +
                (service_exclude_known_ ? 1U : 0U) + (service_exclude_unknown_ ? 1U : 0U) +
                count_configured_service_rows(service_include_text_rows_) +
                count_configured_service_rows(service_exclude_text_rows_)
            : spec.service.include.size() + spec.service.exclude.size();
        break;
    case AdvancedFlowFilterFiniteSection::protocol_path:
        count = document_state_.is_editing()
            ? protocol_path_include_rows_.size() + protocol_path_exclude_rows_.size()
            : static_cast<std::size_t>(std::count_if(
                  spec.protocol_path.include.begin(),
                  spec.protocol_path.include.end(),
                  [](const auto& predicate) { return protocol_path_predicate_is_ui_managed(predicate); }
              )) +
                static_cast<std::size_t>(std::count_if(
                    spec.protocol_path.exclude.begin(),
                    spec.protocol_path.exclude.end(),
                    [](const auto& predicate) { return protocol_path_predicate_is_ui_managed(predicate); }
                ));
        break;
    case AdvancedFlowFilterFiniteSection::contains_layer:
        count = document_state_.is_editing()
            ? count_configured_contains_layer_rows(contains_layer_include_rows_) +
                count_configured_contains_layer_rows(contains_layer_exclude_rows_)
            : static_cast<std::size_t>(std::count_if(
                  spec.protocol_path.include.begin(),
                  spec.protocol_path.include.end(),
                  [](const auto& predicate) { return contains_layer_predicate_is_ui_managed(predicate); }
              )) +
                static_cast<std::size_t>(std::count_if(
                    spec.protocol_path.exclude.begin(),
                    spec.protocol_path.exclude.end(),
                    [](const auto& predicate) { return contains_layer_predicate_is_ui_managed(predicate); }
                ));
        break;
    }

    return static_cast<int>(count);
}

QString AdvancedFlowFilterEditorModel::sectionSummaryText(const int section) const {
    return format_section_summary_text(
        static_cast<std::size_t>(std::max(sectionConfiguredRuleCount(section), 0)),
        sectionEnabled(section)
    );
}

QVariantList AdvancedFlowFilterEditorModel::includeOptions(const int section) const {
    const auto parsed_section = advanced_flow_filter_section_from_int(section);
    if (!parsed_section.has_value()) {
        return {};
    }

    const auto& spec = document_state_.current_user_visible_document().configured_spec;
    switch (*parsed_section) {
    case AdvancedFlowFilterFiniteSection::address_family:
        return build_advanced_filter_option_list(spec.address_family.include, kAdvancedFilterAddressFamilyOptions);
    case AdvancedFlowFilterFiniteSection::flow_protocol:
        return build_advanced_filter_option_list(spec.flow_protocol.include, kAdvancedFilterFlowProtocolOptions);
    case AdvancedFlowFilterFiniteSection::detected_protocol:
        return build_advanced_filter_option_list(spec.detected_protocol.include, kAdvancedFilterDetectedProtocolOptions);
    case AdvancedFlowFilterFiniteSection::tls_version:
        return build_advanced_filter_option_list(spec.tls_version.include, kAdvancedFilterTlsVersionOptions);
    case AdvancedFlowFilterFiniteSection::quic_version:
        return build_advanced_filter_option_list(spec.quic_version.include, kAdvancedFilterQuicVersionOptions);
    case AdvancedFlowFilterFiniteSection::directionality:
        return build_advanced_filter_option_list(spec.directionality.include, kAdvancedFilterDirectionalityOptions);
    case AdvancedFlowFilterFiniteSection::ports:
    case AdvancedFlowFilterFiniteSection::ip_addresses:
    case AdvancedFlowFilterFiniteSection::time:
    case AdvancedFlowFilterFiniteSection::traffic:
    case AdvancedFlowFilterFiniteSection::service:
    case AdvancedFlowFilterFiniteSection::protocol_path:
    case AdvancedFlowFilterFiniteSection::contains_layer:
        return {};
    }

    return {};
}

QVariantList AdvancedFlowFilterEditorModel::excludeOptions(const int section) const {
    const auto parsed_section = advanced_flow_filter_section_from_int(section);
    if (!parsed_section.has_value()) {
        return {};
    }

    const auto& spec = document_state_.current_user_visible_document().configured_spec;
    switch (*parsed_section) {
    case AdvancedFlowFilterFiniteSection::address_family:
        return build_advanced_filter_option_list(spec.address_family.exclude, kAdvancedFilterAddressFamilyOptions);
    case AdvancedFlowFilterFiniteSection::flow_protocol:
        return build_advanced_filter_option_list(spec.flow_protocol.exclude, kAdvancedFilterFlowProtocolOptions);
    case AdvancedFlowFilterFiniteSection::detected_protocol:
        return build_advanced_filter_option_list(spec.detected_protocol.exclude, kAdvancedFilterDetectedProtocolOptions);
    case AdvancedFlowFilterFiniteSection::tls_version:
        return build_advanced_filter_option_list(spec.tls_version.exclude, kAdvancedFilterTlsVersionOptions);
    case AdvancedFlowFilterFiniteSection::quic_version:
        return build_advanced_filter_option_list(spec.quic_version.exclude, kAdvancedFilterQuicVersionOptions);
    case AdvancedFlowFilterFiniteSection::directionality:
        return build_advanced_filter_option_list(spec.directionality.exclude, kAdvancedFilterDirectionalityOptions);
    case AdvancedFlowFilterFiniteSection::ports:
    case AdvancedFlowFilterFiniteSection::ip_addresses:
    case AdvancedFlowFilterFiniteSection::time:
    case AdvancedFlowFilterFiniteSection::traffic:
    case AdvancedFlowFilterFiniteSection::service:
    case AdvancedFlowFilterFiniteSection::protocol_path:
    case AdvancedFlowFilterFiniteSection::contains_layer:
        return {};
    }

    return {};
}

QVariantList AdvancedFlowFilterEditorModel::portScopeOptions() const {
    return build_advanced_filter_static_option_list(kAdvancedFlowFilterPortScopeOptions);
}

QVariantList AdvancedFlowFilterEditorModel::addressScopeOptions() const {
    return build_advanced_filter_static_option_list(kAdvancedFlowFilterAddressScopeOptions);
}

QVariantList AdvancedFlowFilterEditorModel::portRows(const bool exclude) const {
    return buildPortRowList(exclude);
}

QVariantList AdvancedFlowFilterEditorModel::addressRows(const bool exclude) const {
    return buildAddressRowList(exclude);
}

QVariantList AdvancedFlowFilterEditorModel::timeRangeRows() const {
    return buildTimeRangeRowList();
}

QVariantMap AdvancedFlowFilterEditorModel::timeDurationRow() const {
    return buildTimeDurationRow();
}

QVariantList AdvancedFlowFilterEditorModel::commonTrafficRows() const {
    return buildTrafficRowList(TrafficRowGroup::primary);
}

QVariantList AdvancedFlowFilterEditorModel::packetDistributionIncludeOptions() const {
    return build_advanced_filter_option_list(
        document_state_.current_user_visible_document().configured_spec.aggregate.packet_distribution.include,
        kAdvancedFilterTrafficDistributionOptions
    );
}

QVariantList AdvancedFlowFilterEditorModel::packetDistributionExcludeOptions() const {
    return build_advanced_filter_option_list(
        document_state_.current_user_visible_document().configured_spec.aggregate.packet_distribution.exclude,
        kAdvancedFilterTrafficDistributionOptions
    );
}

QVariantList AdvancedFlowFilterEditorModel::dataDistributionIncludeOptions() const {
    return build_advanced_filter_option_list(
        document_state_.current_user_visible_document().configured_spec.aggregate.data_distribution.include,
        kAdvancedFilterTrafficDistributionOptions
    );
}

QVariantList AdvancedFlowFilterEditorModel::dataDistributionExcludeOptions() const {
    return build_advanced_filter_option_list(
        document_state_.current_user_visible_document().configured_spec.aggregate.data_distribution.exclude,
        kAdvancedFilterTrafficDistributionOptions
    );
}

QVariantList AdvancedFlowFilterEditorModel::directionalPacketTrafficRows() const {
    return buildTrafficRowList(TrafficRowGroup::directional_packets);
}

QVariantList AdvancedFlowFilterEditorModel::directionalOriginalByteTrafficRows() const {
    return buildTrafficRowList(TrafficRowGroup::directional_original_bytes);
}

QVariantList AdvancedFlowFilterEditorModel::additionalTrafficRows() const {
    return buildTrafficRowList(TrafficRowGroup::additional);
}

bool AdvancedFlowFilterEditorModel::trafficAdditionalFiltersExpandedSuggested() const noexcept {
    if (document_state_.is_editing()) {
        auto* draft_document = document_state_.draft_document();
        return draft_document != nullptr &&
            any_additional_traffic_metric_active(draft_document->configured_spec.aggregate);
    }
    return any_additional_traffic_metric_active(document_state_.current_user_visible_document().configured_spec.aggregate);
}

void AdvancedFlowFilterEditorModel::setTimeRangeFromText(const QString& metricId, const QString& text) {
    ensureEditingInitialized();
    const auto* descriptor = time_range_descriptor(metricId);
    if (descriptor == nullptr) {
        return;
    }

    const auto index = static_cast<std::size_t>(descriptor - kTimeRangeDescriptors.data());
    if (index >= time_range_rows_.size()) {
        return;
    }

    time_range_rows_[index].from_text = text;
    (void)synchronizeDraftSections();
    notifyTextFieldEdited();
}

void AdvancedFlowFilterEditorModel::setTimeRangeToText(const QString& metricId, const QString& text) {
    ensureEditingInitialized();
    const auto* descriptor = time_range_descriptor(metricId);
    if (descriptor == nullptr) {
        return;
    }

    const auto index = static_cast<std::size_t>(descriptor - kTimeRangeDescriptors.data());
    if (index >= time_range_rows_.size()) {
        return;
    }

    time_range_rows_[index].to_text = text;
    (void)synchronizeDraftSections();
    notifyTextFieldEdited();
}

void AdvancedFlowFilterEditorModel::setTimeDurationMinText(const QString& text) {
    ensureEditingInitialized();
    time_duration_row_.min_text = text;
    (void)synchronizeDraftSections();
    notifyTextFieldEdited();
}

void AdvancedFlowFilterEditorModel::setTimeDurationMaxText(const QString& text) {
    ensureEditingInitialized();
    time_duration_row_.max_text = text;
    (void)synchronizeDraftSections();
    notifyTextFieldEdited();
}

bool AdvancedFlowFilterEditorModel::setTimeDurationUnit(const int unit) {
    ensureEditingInitialized();
    const auto parsed_unit = traffic_unit_from_int(unit);
    if (!parsed_unit.has_value() || !traffic_unit_allowed_for_metric(kTimeDurationDescriptor, *parsed_unit)) {
        return false;
    }

    if (time_duration_row_.unit == *parsed_unit) {
        return true;
    }

    const auto old_unit = time_duration_row_.unit;
    const auto try_convert = [&](QString& value_text) -> bool {
        const auto trimmed = value_text.trimmed();
        if (trimmed.isEmpty()) {
            return true;
        }
        const auto semantic_value = exact_scaled_value_for_text(trimmed, old_unit);
        if (!semantic_value.has_value()) {
            return true;
        }
        const auto new_multiplier = traffic_unit_multiplier(*parsed_unit);
        if (*semantic_value % new_multiplier != 0U) {
            setValidationText(QStringLiteral("Duration unit cannot be changed because current values are not exact in %1.")
                .arg(traffic_unit_label(kTimeDurationDescriptor, *parsed_unit)));
            return false;
        }

        value_text = QString::number(*semantic_value / new_multiplier);
        return true;
    };

    QString min_text = time_duration_row_.min_text;
    QString max_text = time_duration_row_.max_text;
    if (!try_convert(min_text) || !try_convert(max_text)) {
        return false;
    }

    time_duration_row_.unit = *parsed_unit;
    time_duration_row_.min_text = min_text;
    time_duration_row_.max_text = max_text;
    (void)synchronizeDraftSections();
    notifyRowsChanged();
    return true;
}

bool AdvancedFlowFilterEditorModel::serviceStateChecked(const bool exclude, const int stateKind) const noexcept {
    const auto kind = static_cast<session_detail::AdvancedFlowFilterServicePredicateKind>(stateKind);
    if (!service_kind_is_state(kind)) {
        return false;
    }

    if (document_state_.is_editing()) {
        if (!exclude) {
            return kind == session_detail::AdvancedFlowFilterServicePredicateKind::known
                ? service_include_known_
                : service_include_unknown_;
        }
        return kind == session_detail::AdvancedFlowFilterServicePredicateKind::known
            ? service_exclude_known_
            : service_exclude_unknown_;
    }

    const auto& predicates = exclude
        ? document_state_.current_user_visible_document().configured_spec.service.exclude
        : document_state_.current_user_visible_document().configured_spec.service.include;
    return std::any_of(predicates.begin(), predicates.end(), [&](const auto& predicate) {
        return predicate.kind == kind;
    });
}

bool AdvancedFlowFilterEditorModel::serviceTextRulesEditable(const bool exclude) const noexcept {
    if (exclude) {
        return true;
    }

    if (document_state_.is_editing()) {
        return !service_text_rules_disabled_for_include_state(service_include_known_, service_include_unknown_);
    }

    bool include_known = false;
    bool include_unknown = false;
    for (const auto& predicate : document_state_.current_user_visible_document().configured_spec.service.include) {
        if (predicate.kind == session_detail::AdvancedFlowFilterServicePredicateKind::known) {
            include_known = true;
        } else if (predicate.kind == session_detail::AdvancedFlowFilterServicePredicateKind::unknown) {
            include_unknown = true;
        }
    }
    return !service_text_rules_disabled_for_include_state(include_known, include_unknown);
}

QVariantList AdvancedFlowFilterEditorModel::serviceOperatorOptions() const {
    return build_advanced_filter_static_option_list(kAdvancedFlowFilterServiceOperatorOptions);
}

QVariantList AdvancedFlowFilterEditorModel::serviceTextRows(const bool exclude) const {
    return buildServiceTextRowList(exclude);
}

QVariantList AdvancedFlowFilterEditorModel::protocolPathRows(const bool exclude) const {
    return buildProtocolPathRowList(exclude);
}

QVariantList AdvancedFlowFilterEditorModel::containsLayerRows(const bool exclude) const {
    return buildContainsLayerRowList(exclude);
}

QVariantList AdvancedFlowFilterEditorModel::containsLayerOptions() const {
    return build_contains_layer_option_list();
}

QVariantList AdvancedFlowFilterEditorModel::containsLayerIdentifierModeOptions() const {
    return build_advanced_filter_static_option_list(kAdvancedFlowFilterContainsLayerIdentifierModeOptions);
}

void AdvancedFlowFilterEditorModel::setTrafficMinText(const int metric, const QString& text) {
    ensureEditingInitialized();
    const auto parsed_metric = traffic_metric_from_int(metric);
    if (!parsed_metric.has_value()) {
        return;
    }

    const auto index = static_cast<std::size_t>(*parsed_metric);
    if (index >= traffic_rows_.size()) {
        return;
    }

    traffic_rows_[index].min_text = text;
    (void)synchronizeDraftSections();
    notifyTextFieldEdited();
}

void AdvancedFlowFilterEditorModel::setTrafficMaxText(const int metric, const QString& text) {
    ensureEditingInitialized();
    const auto parsed_metric = traffic_metric_from_int(metric);
    if (!parsed_metric.has_value()) {
        return;
    }

    const auto index = static_cast<std::size_t>(*parsed_metric);
    if (index >= traffic_rows_.size()) {
        return;
    }

    traffic_rows_[index].max_text = text;
    (void)synchronizeDraftSections();
    notifyTextFieldEdited();
}

bool AdvancedFlowFilterEditorModel::setTrafficUnit(const int metric, const int unit) {
    ensureEditingInitialized();
    const auto parsed_metric = traffic_metric_from_int(metric);
    const auto parsed_unit = traffic_unit_from_int(unit);
    if (!parsed_metric.has_value() || !parsed_unit.has_value()) {
        return false;
    }

    const auto* descriptor = traffic_metric_descriptor(*parsed_metric);
    if (descriptor == nullptr || !traffic_metric_has_unit_selector(*descriptor) ||
        !traffic_unit_allowed_for_metric(*descriptor, *parsed_unit)) {
        return false;
    }

    auto& row = traffic_rows_[static_cast<std::size_t>(*parsed_metric)];
    if (row.unit == *parsed_unit) {
        return true;
    }

    const auto old_unit = row.unit;
    const auto try_convert = [&](QString& value_text) -> bool {
        const auto trimmed = value_text.trimmed();
        if (trimmed.isEmpty()) {
            return true;
        }
        const auto semantic_value = exact_scaled_value_for_text(trimmed, old_unit);
        if (!semantic_value.has_value()) {
            return true;
        }
        const auto new_multiplier = traffic_unit_multiplier(*parsed_unit);
        if (*semantic_value % new_multiplier != 0U) {
            setValidationText(QStringLiteral("%1 unit cannot be changed because current values are not exact in %2.")
                .arg(QString::fromLatin1(descriptor->label))
                .arg(traffic_unit_label(*descriptor, *parsed_unit)));
            return false;
        }

        value_text = QString::number(*semantic_value / new_multiplier);
        return true;
    };

    QString min_text = row.min_text;
    QString max_text = row.max_text;
    if (!try_convert(min_text) || !try_convert(max_text)) {
        return false;
    }

    row.unit = *parsed_unit;
    row.min_text = min_text;
    row.max_text = max_text;
    (void)synchronizeDraftSections();
    notifyRowsChanged();
    return true;
}

void AdvancedFlowFilterEditorModel::setTrafficDistributionOptionChecked(
    const bool dataDistribution,
    const int value,
    const bool exclude,
    const bool checked
) {
    ensureEditingInitialized();
    auto* draft_document = document_state_.draft_document();
    if (draft_document == nullptr) {
        return;
    }

    auto& criteria = dataDistribution
        ? draft_document->configured_spec.aggregate.data_distribution
        : draft_document->configured_spec.aggregate.packet_distribution;
    auto& values = exclude ? criteria.exclude : criteria.include;
    if (!set_advanced_filter_option_checked(values, static_cast<DirectionDistribution>(value), checked)) {
        return;
    }

    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::setServiceStateChecked(const bool exclude, const int stateKind, const bool checked) {
    ensureEditingInitialized();
    const auto kind = static_cast<session_detail::AdvancedFlowFilterServicePredicateKind>(stateKind);
    if (!service_kind_is_state(kind)) {
        return;
    }

    bool* target = nullptr;
    if (!exclude) {
        target = kind == session_detail::AdvancedFlowFilterServicePredicateKind::known
            ? &service_include_known_
            : &service_include_unknown_;
    } else {
        target = kind == session_detail::AdvancedFlowFilterServicePredicateKind::known
            ? &service_exclude_known_
            : &service_exclude_unknown_;
    }

    if (target == nullptr || *target == checked) {
        return;
    }

    *target = checked;
    (void)synchronizeDraftSections();
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::addServiceTextRow(const bool exclude) {
    ensureEditingInitialized();
    if (!exclude && !serviceTextRulesEditable(false)) {
        return;
    }
    auto& rows = exclude ? service_exclude_text_rows_ : service_include_text_rows_;
    rows.push_back({});
    (void)synchronizeDraftSections();
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::removeServiceTextRow(const bool exclude, const int row) {
    ensureEditingInitialized();
    auto& rows = exclude ? service_exclude_text_rows_ : service_include_text_rows_;
    if (row < 0 || static_cast<std::size_t>(row) >= rows.size()) {
        return;
    }

    rows.erase(rows.begin() + row);
    (void)synchronizeDraftSections();
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::setServiceTextRowKind(const bool exclude, const int row, const int kind) {
    ensureEditingInitialized();
    if (!exclude && !serviceTextRulesEditable(false)) {
        return;
    }
    auto& rows = exclude ? service_exclude_text_rows_ : service_include_text_rows_;
    if (row < 0 || static_cast<std::size_t>(row) >= rows.size()) {
        return;
    }

    const auto parsed_kind = static_cast<session_detail::AdvancedFlowFilterServicePredicateKind>(kind);
    if (parsed_kind != session_detail::AdvancedFlowFilterServicePredicateKind::equals &&
        parsed_kind != session_detail::AdvancedFlowFilterServicePredicateKind::starts_with &&
        parsed_kind != session_detail::AdvancedFlowFilterServicePredicateKind::contains) {
        return;
    }

    rows[static_cast<std::size_t>(row)].kind = parsed_kind;
    (void)synchronizeDraftSections();
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::setServiceTextRowCaseSensitive(
    const bool exclude,
    const int row,
    const bool caseSensitive
) {
    ensureEditingInitialized();
    if (!exclude && !serviceTextRulesEditable(false)) {
        return;
    }
    auto& rows = exclude ? service_exclude_text_rows_ : service_include_text_rows_;
    if (row < 0 || static_cast<std::size_t>(row) >= rows.size()) {
        return;
    }

    rows[static_cast<std::size_t>(row)].case_sensitive = caseSensitive;
    (void)synchronizeDraftSections();
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::setServiceTextRowText(const bool exclude, const int row, const QString& text) {
    ensureEditingInitialized();
    if (!exclude && !serviceTextRulesEditable(false)) {
        return;
    }
    auto& rows = exclude ? service_exclude_text_rows_ : service_include_text_rows_;
    if (row < 0 || static_cast<std::size_t>(row) >= rows.size()) {
        return;
    }

    rows[static_cast<std::size_t>(row)].text = text;
    (void)synchronizeDraftSections();
    notifyTextFieldEdited();
}

void AdvancedFlowFilterEditorModel::setSectionEnabled(const int section, const bool enabled) {
    const auto parsed_section = advanced_flow_filter_section_from_int(section);
    if (!parsed_section.has_value()) {
        return;
    }

    document_state_.begin_edit();
    auto* draft_document = document_state_.draft_document();
    if (draft_document == nullptr) {
        return;
    }

    auto* section_enabled = advanced_flow_filter_section_enabled_mutable(draft_document->section_states, *parsed_section);
    if (section_enabled == nullptr || *section_enabled == enabled) {
        return;
    }

    *section_enabled = enabled;
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::setOptionChecked(
    const int section,
    const int value,
    const bool exclude,
    const bool checked
) {
    const auto parsed_section = advanced_flow_filter_section_from_int(section);
    if (!parsed_section.has_value()) {
        return;
    }

    document_state_.begin_edit();
    auto* draft_document = document_state_.draft_document();
    if (draft_document == nullptr) {
        return;
    }

    bool changed = false;
    switch (*parsed_section) {
    case AdvancedFlowFilterFiniteSection::address_family:
        changed = set_advanced_filter_option_checked(
            exclude ? draft_document->configured_spec.address_family.exclude : draft_document->configured_spec.address_family.include,
            static_cast<FlowAddressFamily>(value),
            checked
        );
        break;
    case AdvancedFlowFilterFiniteSection::flow_protocol:
        changed = set_advanced_filter_option_checked(
            exclude ? draft_document->configured_spec.flow_protocol.exclude : draft_document->configured_spec.flow_protocol.include,
            static_cast<ProtocolId>(value),
            checked
        );
        break;
    case AdvancedFlowFilterFiniteSection::detected_protocol:
        changed = set_advanced_filter_option_checked(
            exclude ? draft_document->configured_spec.detected_protocol.exclude : draft_document->configured_spec.detected_protocol.include,
            static_cast<FlowProtocolHint>(value),
            checked
        );
        break;
    case AdvancedFlowFilterFiniteSection::tls_version:
        changed = set_advanced_filter_option_checked(
            exclude ? draft_document->configured_spec.tls_version.exclude : draft_document->configured_spec.tls_version.include,
            static_cast<TlsVersionHint>(value),
            checked
        );
        break;
    case AdvancedFlowFilterFiniteSection::quic_version:
        changed = set_advanced_filter_option_checked(
            exclude ? draft_document->configured_spec.quic_version.exclude : draft_document->configured_spec.quic_version.include,
            static_cast<QuicVersionHint>(value),
            checked
        );
        break;
    case AdvancedFlowFilterFiniteSection::directionality:
        changed = set_advanced_filter_option_checked(
            exclude ? draft_document->configured_spec.directionality.exclude : draft_document->configured_spec.directionality.include,
            static_cast<session_detail::AdvancedFlowFilterDirectionality>(value),
            checked
        );
        break;
    case AdvancedFlowFilterFiniteSection::ports:
    case AdvancedFlowFilterFiniteSection::ip_addresses:
    case AdvancedFlowFilterFiniteSection::time:
    case AdvancedFlowFilterFiniteSection::traffic:
    case AdvancedFlowFilterFiniteSection::service:
    case AdvancedFlowFilterFiniteSection::protocol_path:
    case AdvancedFlowFilterFiniteSection::contains_layer:
        break;
    }

    if (changed) {
        notifyRowsChanged();
    }
}

void AdvancedFlowFilterEditorModel::addPortRow(const bool exclude) {
    ensureEditingInitialized();
    if (!document_state_.is_editing()) {
        return;
    }

    auto& rows = exclude ? port_exclude_rows_ : port_include_rows_;
    rows.push_back({});
    (void)synchronizeDraftSections();
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::removePortRow(const bool exclude, const int row) {
    auto& rows = exclude ? port_exclude_rows_ : port_include_rows_;
    if (row < 0 || static_cast<std::size_t>(row) >= rows.size()) {
        return;
    }

    rows.erase(rows.begin() + row);
    (void)synchronizeDraftSections();
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::setPortRowScope(const bool exclude, const int row, const int scope) {
    auto& rows = exclude ? port_exclude_rows_ : port_include_rows_;
    if (row < 0 || static_cast<std::size_t>(row) >= rows.size()) {
        return;
    }

    rows[static_cast<std::size_t>(row)].scope = static_cast<session_detail::AdvancedFlowFilterPortScope>(scope);
    (void)synchronizeDraftSections();
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::setPortRowRangeEnabled(const bool exclude, const int row, const bool enabled) {
    auto& rows = exclude ? port_exclude_rows_ : port_include_rows_;
    if (row < 0 || static_cast<std::size_t>(row) >= rows.size()) {
        return;
    }

    rows[static_cast<std::size_t>(row)].range_enabled = enabled;
    (void)synchronizeDraftSections();
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::setPortRowPrimaryText(const bool exclude, const int row, const QString& text) {
    auto& rows = exclude ? port_exclude_rows_ : port_include_rows_;
    if (row < 0 || static_cast<std::size_t>(row) >= rows.size()) {
        return;
    }

    rows[static_cast<std::size_t>(row)].primary_text = text;
    (void)synchronizeDraftSections();
    notifyTextFieldEdited();
}

void AdvancedFlowFilterEditorModel::setPortRowSecondaryText(const bool exclude, const int row, const QString& text) {
    auto& rows = exclude ? port_exclude_rows_ : port_include_rows_;
    if (row < 0 || static_cast<std::size_t>(row) >= rows.size()) {
        return;
    }

    rows[static_cast<std::size_t>(row)].secondary_text = text;
    (void)synchronizeDraftSections();
    notifyTextFieldEdited();
}

void AdvancedFlowFilterEditorModel::addAddressRow(const bool exclude) {
    ensureEditingInitialized();
    if (!document_state_.is_editing()) {
        return;
    }

    auto& rows = exclude ? address_exclude_rows_ : address_include_rows_;
    rows.push_back({});
    (void)synchronizeDraftSections();
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::removeAddressRow(const bool exclude, const int row) {
    auto& rows = exclude ? address_exclude_rows_ : address_include_rows_;
    if (row < 0 || static_cast<std::size_t>(row) >= rows.size()) {
        return;
    }

    rows.erase(rows.begin() + row);
    (void)synchronizeDraftSections();
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::setAddressRowScope(const bool exclude, const int row, const int scope) {
    auto& rows = exclude ? address_exclude_rows_ : address_include_rows_;
    if (row < 0 || static_cast<std::size_t>(row) >= rows.size()) {
        return;
    }

    rows[static_cast<std::size_t>(row)].scope = static_cast<session_detail::AdvancedFlowFilterEndpointScope>(scope);
    (void)synchronizeDraftSections();
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::setAddressRowSubnetEnabled(const bool exclude, const int row, const bool enabled) {
    auto& rows = exclude ? address_exclude_rows_ : address_include_rows_;
    if (row < 0 || static_cast<std::size_t>(row) >= rows.size()) {
        return;
    }

    rows[static_cast<std::size_t>(row)].subnet_enabled = enabled;
    (void)synchronizeDraftSections();
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::setAddressRowAddressText(const bool exclude, const int row, const QString& text) {
    auto& rows = exclude ? address_exclude_rows_ : address_include_rows_;
    if (row < 0 || static_cast<std::size_t>(row) >= rows.size()) {
        return;
    }

    rows[static_cast<std::size_t>(row)].address_text = text;
    (void)synchronizeDraftSections();
    notifyTextFieldEdited();
}

void AdvancedFlowFilterEditorModel::setAddressRowPrefixText(const bool exclude, const int row, const QString& text) {
    auto& rows = exclude ? address_exclude_rows_ : address_include_rows_;
    if (row < 0 || static_cast<std::size_t>(row) >= rows.size()) {
        return;
    }

    rows[static_cast<std::size_t>(row)].prefix_text = text;
    (void)synchronizeDraftSections();
    notifyTextFieldEdited();
}

void AdvancedFlowFilterEditorModel::addContainsLayerRow(const bool exclude) {
    ensureEditingInitialized();
    if (!document_state_.is_editing()) {
        return;
    }

    auto& rows = exclude ? contains_layer_exclude_rows_ : contains_layer_include_rows_;
    rows.push_back(AdvancedFlowFilterContainsLayerEditorRow {
        .kind = default_contains_layer_kind(),
        .identifier_mode = AdvancedFlowFilterContainsLayerIdentifierMode::any,
        .exact_value_text = {},
        .applicable = std::nullopt,
    });
    if (!rows.empty()) {
        rows.back().applicable = contains_layer_row_applicability(rows.back(), protocol_path_applicability_resolver_);
    }
    (void)synchronizeDraftSections();
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::removeContainsLayerRow(const bool exclude, const int row) {
    auto& rows = exclude ? contains_layer_exclude_rows_ : contains_layer_include_rows_;
    if (row < 0 || static_cast<std::size_t>(row) >= rows.size()) {
        return;
    }

    rows.erase(rows.begin() + row);
    (void)synchronizeDraftSections();
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::setContainsLayerRowKind(const bool exclude, const int row, const int kind) {
    auto& rows = exclude ? contains_layer_exclude_rows_ : contains_layer_include_rows_;
    if (row < 0 || static_cast<std::size_t>(row) >= rows.size()) {
        return;
    }

    const auto parsed_kind = contains_layer_kind_from_int(kind);
    if (!parsed_kind.has_value()) {
        return;
    }

    auto& editor_row = rows[static_cast<std::size_t>(row)];
    editor_row.kind = *parsed_kind;
    editor_row.exact_value_text.clear();
    editor_row.applicable = contains_layer_row_applicability(editor_row, protocol_path_applicability_resolver_);
    (void)synchronizeDraftSections();
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::setContainsLayerRowIdentifierMode(
    const bool exclude,
    const int row,
    const int mode
) {
    auto& rows = exclude ? contains_layer_exclude_rows_ : contains_layer_include_rows_;
    if (row < 0 || static_cast<std::size_t>(row) >= rows.size()) {
        return;
    }

    const auto parsed_mode = contains_layer_identifier_mode_from_int(mode);
    if (!parsed_mode.has_value()) {
        return;
    }

    auto& editor_row = rows[static_cast<std::size_t>(row)];
    editor_row.identifier_mode = *parsed_mode;
    editor_row.applicable = contains_layer_row_applicability(editor_row, protocol_path_applicability_resolver_);
    (void)synchronizeDraftSections();
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::setContainsLayerRowExactValueText(
    const bool exclude,
    const int row,
    const QString& text
) {
    auto& rows = exclude ? contains_layer_exclude_rows_ : contains_layer_include_rows_;
    if (row < 0 || static_cast<std::size_t>(row) >= rows.size()) {
        return;
    }

    auto& editor_row = rows[static_cast<std::size_t>(row)];
    editor_row.exact_value_text = text;
    editor_row.applicable = contains_layer_row_applicability(editor_row, protocol_path_applicability_resolver_);
    (void)synchronizeDraftSections();
    notifyTextFieldEdited();
}

void AdvancedFlowFilterEditorModel::removeProtocolPathRow(const bool exclude, const int row) {
    ensureEditingInitialized();
    auto& rows = exclude ? protocol_path_exclude_rows_ : protocol_path_include_rows_;
    if (row < 0 || static_cast<std::size_t>(row) >= rows.size()) {
        return;
    }

    rows.erase(rows.begin() + row);
    (void)synchronizeDraftSections();
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::setProtocolPathApplicabilityResolver(
    std::function<std::optional<bool>(const session_detail::AdvancedFlowFilterProtocolPathPredicate&)> resolver
) {
    protocol_path_applicability_resolver_ = std::move(resolver);
    refreshProtocolPathApplicability();
}

void AdvancedFlowFilterEditorModel::upsertProtocolPathRow(
    const bool exclude,
    const int row,
    const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate,
    const ProtocolPathStatisticsMode selectorMode
) {
    ensureEditingInitialized();
    if (!protocol_path_predicate_is_ui_managed(predicate)) {
        return;
    }

    auto& rows = exclude ? protocol_path_exclude_rows_ : protocol_path_include_rows_;
    AdvancedFlowFilterProtocolPathEditorRow editor_row {
        .predicate = predicate,
        .selector_mode = selectorMode,
        .applicable = protocol_path_applicability_resolver_
            ? protocol_path_applicability_resolver_(predicate)
            : std::nullopt,
    };
    if (row >= 0 && static_cast<std::size_t>(row) < rows.size()) {
        rows[static_cast<std::size_t>(row)] = std::move(editor_row);
    } else {
        rows.push_back(std::move(editor_row));
    }

    (void)synchronizeDraftSections();
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::refreshProtocolPathApplicability() {
    const auto refresh_rows = [&](auto& rows) {
        for (auto& row : rows) {
            row.applicable = protocol_path_applicability_resolver_
                ? protocol_path_applicability_resolver_(row.predicate)
                : std::nullopt;
        }
    };

    refresh_rows(protocol_path_include_rows_);
    refresh_rows(protocol_path_exclude_rows_);
    const auto refresh_contains_rows = [&](auto& rows) {
        for (auto& row : rows) {
            row.applicable = contains_layer_row_applicability(row, protocol_path_applicability_resolver_);
        }
    };
    refresh_contains_rows(contains_layer_include_rows_);
    refresh_contains_rows(contains_layer_exclude_rows_);
    notifyStateChanged();
}

void AdvancedFlowFilterEditorModel::initializeFromCurrentDocument() {
    const auto& document = document_state_.current_user_visible_document();
    port_include_rows_.clear();
    port_exclude_rows_.clear();
    address_include_rows_.clear();
    address_exclude_rows_.clear();
    time_range_rows_.assign(kTimeRangeDescriptors.size(), {});
    time_duration_row_ = {};
    traffic_rows_.assign(
        static_cast<std::size_t>(AdvancedFlowFilterTrafficMetric::b_to_a_original_bytes) + 1U,
        {}
    );
    service_include_known_ = false;
    service_include_unknown_ = false;
    service_exclude_known_ = false;
    service_exclude_unknown_ = false;
    service_include_text_rows_.clear();
    service_exclude_text_rows_.clear();
    protocol_path_include_rows_.clear();
    protocol_path_exclude_rows_.clear();
    contains_layer_include_rows_.clear();
    contains_layer_exclude_rows_.clear();

    const auto append_port_rows =
        [](const auto& predicates, std::vector<AdvancedFlowFilterPortEditorRow>& rows) {
            rows.reserve(predicates.size());
            for (const auto& predicate : predicates) {
                rows.push_back(AdvancedFlowFilterPortEditorRow {
                    .scope = predicate.scope,
                    .range_enabled = predicate.range.first != predicate.range.last,
                    .primary_text = QString::number(predicate.range.first),
                    .secondary_text = predicate.range.first == predicate.range.last
                        ? QString {}
                        : QString::number(predicate.range.last),
                });
            }
        };
    append_port_rows(document.configured_spec.ports.include, port_include_rows_);
    append_port_rows(document.configured_spec.ports.exclude, port_exclude_rows_);

    const auto append_ipv4_rows =
        [](const auto& predicates, std::vector<AdvancedFlowFilterAddressEditorRow>& rows) {
            rows.reserve(rows.size() + predicates.size());
            for (const auto& predicate : predicates) {
                rows.push_back(AdvancedFlowFilterAddressEditorRow {
                    .scope = predicate.scope,
                    .subnet_enabled = predicate.match_kind == session_detail::AdvancedFlowFilterAddressMatchKind::cidr,
                    .address_text = formatIpv4Address(predicate.value),
                    .prefix_text = predicate.match_kind == session_detail::AdvancedFlowFilterAddressMatchKind::cidr
                        ? QString::number(predicate.prefix_length)
                        : QString {},
                });
            }
        };
    const auto append_ipv6_rows =
        [](const auto& predicates, std::vector<AdvancedFlowFilterAddressEditorRow>& rows) {
            rows.reserve(rows.size() + predicates.size());
            for (const auto& predicate : predicates) {
                rows.push_back(AdvancedFlowFilterAddressEditorRow {
                    .scope = predicate.scope,
                    .subnet_enabled = predicate.match_kind == session_detail::AdvancedFlowFilterAddressMatchKind::cidr,
                    .address_text = formatIpv6Address(predicate.value),
                    .prefix_text = predicate.match_kind == session_detail::AdvancedFlowFilterAddressMatchKind::cidr
                        ? QString::number(predicate.prefix_length)
                        : QString {},
                });
            }
        };
    append_ipv4_rows(document.configured_spec.addresses.ipv4_include, address_include_rows_);
    append_ipv6_rows(document.configured_spec.addresses.ipv6_include, address_include_rows_);
    append_ipv4_rows(document.configured_spec.addresses.ipv4_exclude, address_exclude_rows_);
    append_ipv6_rows(document.configured_spec.addresses.ipv6_exclude, address_exclude_rows_);

    for (std::size_t index = 0; index < kTimeRangeDescriptors.size(); ++index) {
        const auto& descriptor = kTimeRangeDescriptors[index];
        const auto range = time_range_u64(document.configured_spec.time, QString::fromLatin1(descriptor.metric_id));
        auto& row = time_range_rows_[index];
        row.from_text = range.has_value() && range->min.has_value()
            ? QString::fromStdString(
                session_detail::format_advanced_flow_filter_utc_timestamp_text(*range->min).value_or(std::string {}))
            : QString {};
        row.to_text = range.has_value() && range->max.has_value()
            ? QString::fromStdString(
                session_detail::format_advanced_flow_filter_utc_timestamp_text(*range->max).value_or(std::string {}))
            : QString {};
    }

    {
        const auto range = load_u64_range(document.configured_spec.time.duration_us);
        const auto unit = choose_largest_exact_unit(
            kTimeDurationDescriptor,
            range.has_value() ? range->min : std::nullopt,
            range.has_value() ? range->max : std::nullopt
        );
        time_duration_row_.unit = unit;
        time_duration_row_.min_text = format_scaled_integer_text(range.has_value() ? range->min : std::nullopt, unit);
        time_duration_row_.max_text = format_scaled_integer_text(range.has_value() ? range->max : std::nullopt, unit);
    }

    const auto initialize_traffic_rows = [&](const auto& descriptors) {
        for (const auto& descriptor : descriptors) {
            const auto range = traffic_metric_range_u64(document.configured_spec.aggregate, descriptor.metric);
            const auto unit = choose_largest_exact_unit(
                descriptor,
                range.has_value() ? range->min : std::nullopt,
                range.has_value() ? range->max : std::nullopt
            );
            auto& row = traffic_rows_[static_cast<std::size_t>(descriptor.metric)];
            row.unit = unit;
            row.min_text = format_scaled_integer_text(range.has_value() ? range->min : std::nullopt, unit);
            row.max_text = format_scaled_integer_text(range.has_value() ? range->max : std::nullopt, unit);
        }
    };
    initialize_traffic_rows(kTrafficMetricDescriptors);
    initialize_traffic_rows(kDirectionalTrafficMetricDescriptors);

    const auto append_service_rows =
        [](const std::vector<session_detail::AdvancedFlowFilterServicePredicate>& predicates,
            bool& known_flag,
            bool& unknown_flag,
            std::vector<AdvancedFlowFilterServiceTextEditorRow>& rows) {
            for (const auto& predicate : predicates) {
                switch (predicate.kind) {
                case session_detail::AdvancedFlowFilterServicePredicateKind::known:
                    known_flag = true;
                    break;
                case session_detail::AdvancedFlowFilterServicePredicateKind::unknown:
                    unknown_flag = true;
                    break;
                case session_detail::AdvancedFlowFilterServicePredicateKind::equals:
                case session_detail::AdvancedFlowFilterServicePredicateKind::starts_with:
                case session_detail::AdvancedFlowFilterServicePredicateKind::contains:
                    rows.push_back(AdvancedFlowFilterServiceTextEditorRow {
                        .kind = predicate.kind,
                        .case_sensitive = predicate.case_sensitivity ==
                            session_detail::AdvancedFlowFilterStringCaseSensitivity::case_sensitive,
                        .text = QString::fromStdString(predicate.value),
                    });
                    break;
                }
            }
        };
    append_service_rows(
        document.configured_spec.service.include,
        service_include_known_,
        service_include_unknown_,
        service_include_text_rows_
    );
    append_service_rows(
        document.configured_spec.service.exclude,
        service_exclude_known_,
        service_exclude_unknown_,
        service_exclude_text_rows_
    );

    const auto append_protocol_path_rows =
        [&](const auto& predicates, std::vector<AdvancedFlowFilterProtocolPathEditorRow>& rows) {
            for (const auto& predicate : predicates) {
                if (!protocol_path_predicate_is_ui_managed(predicate)) {
                    continue;
                }

                rows.push_back(AdvancedFlowFilterProtocolPathEditorRow {
                    .predicate = predicate,
                    .selector_mode = protocol_path_selector_mode_from_predicate(predicate),
                    .applicable = protocol_path_applicability_resolver_
                        ? protocol_path_applicability_resolver_(predicate)
                        : std::nullopt,
                });
            }
        };
    append_protocol_path_rows(document.configured_spec.protocol_path.include, protocol_path_include_rows_);
    append_protocol_path_rows(document.configured_spec.protocol_path.exclude, protocol_path_exclude_rows_);

    const auto append_contains_layer_rows =
        [&](const auto& predicates, std::vector<AdvancedFlowFilterContainsLayerEditorRow>& rows) {
            for (const auto& predicate : predicates) {
                if (!contains_layer_predicate_is_ui_managed(predicate) || predicate.layers.size() != 1U) {
                    continue;
                }

                const auto& layer = predicate.layers.front();
                const auto* descriptor = session_detail::protocol_path_contains_layer_descriptor(layer.kind);
                if (descriptor == nullptr) {
                    continue;
                }

                rows.push_back(AdvancedFlowFilterContainsLayerEditorRow {
                    .kind = descriptor->kind,
                    .identifier_mode = layer.identifier.has_value()
                        ? AdvancedFlowFilterContainsLayerIdentifierMode::exact
                        : AdvancedFlowFilterContainsLayerIdentifierMode::any,
                    .exact_value_text = layer.identifier.has_value()
                        ? QString::fromStdString(session_detail::format_protocol_path_identifier_editor_text(
                              layer.identifier->kind,
                              layer.identifier->value
                          ))
                        : QString {},
                    .applicable = protocol_path_applicability_resolver_
                        ? protocol_path_applicability_resolver_(predicate)
                        : std::nullopt,
                });
            }
        };
    append_contains_layer_rows(document.configured_spec.protocol_path.include, contains_layer_include_rows_);
    append_contains_layer_rows(document.configured_spec.protocol_path.exclude, contains_layer_exclude_rows_);

    editing_initialized_ = true;
    setHasUnsynchronizedBufferedChanges(false);
    ++document_reload_revision_;
    emit documentReloadRevisionChanged();
    clearValidationText();
    notifyStateChanged();
}

void AdvancedFlowFilterEditorModel::clearTransientState() noexcept {
    port_include_rows_.clear();
    port_exclude_rows_.clear();
    address_include_rows_.clear();
    address_exclude_rows_.clear();
    time_range_rows_.clear();
    time_duration_row_ = {};
    traffic_rows_.clear();
    service_include_known_ = false;
    service_include_unknown_ = false;
    service_exclude_known_ = false;
    service_exclude_unknown_ = false;
    service_include_text_rows_.clear();
    service_exclude_text_rows_.clear();
    protocol_path_include_rows_.clear();
    protocol_path_exclude_rows_.clear();
    contains_layer_include_rows_.clear();
    contains_layer_exclude_rows_.clear();
    editing_initialized_ = false;
    setHasUnsynchronizedBufferedChanges(false);
    ++document_reload_revision_;
    emit documentReloadRevisionChanged();
    validation_text_.clear();
    notifyStateChanged();
}

bool AdvancedFlowFilterEditorModel::synchronizeDraftSections(QString* errorText) {
    const bool synchronized = synchronizeDraftSectionsImpl(errorText);
    setHasUnsynchronizedBufferedChanges(!synchronized);
    return synchronized;
}

bool AdvancedFlowFilterEditorModel::synchronizeDraftSectionsImpl(QString* errorText) {
    auto* draft_document = document_state_.draft_document();
    if (draft_document == nullptr) {
        if (errorText != nullptr) {
            *errorText = QStringLiteral("Advanced Filter draft is unavailable.");
        }
        return false;
    }

    auto updated_ports = draft_document->configured_spec.ports;
    auto updated_protocol_path = draft_document->configured_spec.protocol_path;
    const auto strip_protocol_path_selection_predicates = [](auto& predicates) {
        predicates.erase(
            std::remove_if(
                predicates.begin(),
                predicates.end(),
                [](const auto& predicate) { return protocol_path_predicate_is_ui_managed(predicate); }
            ),
            predicates.end()
        );
    };
    strip_protocol_path_selection_predicates(updated_protocol_path.include);
    strip_protocol_path_selection_predicates(updated_protocol_path.exclude);
    if (draft_document->section_states.contains_layer) {
        const auto strip_contains_layer_predicates = [](auto& predicates) {
            predicates.erase(
                std::remove_if(
                    predicates.begin(),
                    predicates.end(),
                    [](const auto& predicate) { return contains_layer_predicate_is_ui_managed(predicate); }
                ),
                predicates.end()
            );
        };
        strip_contains_layer_predicates(updated_protocol_path.include);
        strip_contains_layer_predicates(updated_protocol_path.exclude);
    }
    const auto append_port_rows =
        [&](const std::vector<AdvancedFlowFilterPortEditorRow>& rows,
            const bool exclude,
            const QString& family_label) -> bool {
            auto& target = exclude ? updated_ports.exclude : updated_ports.include;
            for (std::size_t index = 0; index < rows.size(); ++index) {
                const auto& row = rows[index];
                const auto primary = row.primary_text.trimmed();
                const auto secondary = row.secondary_text.trimmed();
                if (!row.range_enabled) {
                    if (primary.isEmpty()) {
                        continue;
                    }

                    const auto port = parse_ui_u32_text(primary);
                    if (!port.has_value() || *port > 65535U) {
                        if (errorText != nullptr) {
                            *errorText = QStringLiteral("%1 row %2: Port must be an integer between 0 and 65535.")
                                .arg(family_label)
                                .arg(QString::number(index + 1U));
                        }
                        return false;
                    }

                    target.push_back(session_detail::AdvancedFlowFilterPortPredicate {
                        .scope = row.scope,
                        .range = {
                            static_cast<std::uint16_t>(*port),
                            static_cast<std::uint16_t>(*port),
                        },
                    });
                    continue;
                }

                if (primary.isEmpty() && secondary.isEmpty()) {
                    continue;
                }
                if (primary.isEmpty() || secondary.isEmpty()) {
                    if (errorText != nullptr) {
                        *errorText = QStringLiteral("%1 row %2: Range rules require both From and To values.")
                            .arg(family_label)
                            .arg(QString::number(index + 1U));
                    }
                    return false;
                }

                const auto first = parse_ui_u32_text(primary);
                const auto last = parse_ui_u32_text(secondary);
                if (!first.has_value() || !last.has_value() || *first > 65535U || *last > 65535U) {
                    if (errorText != nullptr) {
                        *errorText = QStringLiteral("%1 row %2: Range bounds must be integers between 0 and 65535.")
                            .arg(family_label)
                            .arg(QString::number(index + 1U));
                    }
                    return false;
                }
                if (*first > *last) {
                    if (errorText != nullptr) {
                        *errorText = QStringLiteral("%1 row %2: From must be less than or equal to To.")
                            .arg(family_label)
                            .arg(QString::number(index + 1U));
                    }
                    return false;
                }

                target.push_back(session_detail::AdvancedFlowFilterPortPredicate {
                    .scope = row.scope,
                    .range = {
                        static_cast<std::uint16_t>(*first),
                        static_cast<std::uint16_t>(*last),
                    },
                });
            }
            return true;
        };

    if (draft_document->section_states.ports) {
        updated_ports = {};
        if (!append_port_rows(port_include_rows_, false, QStringLiteral("Ports include")) ||
            !append_port_rows(port_exclude_rows_, true, QStringLiteral("Ports exclude"))) {
            return false;
        }
    }

    auto updated_addresses = draft_document->configured_spec.addresses;
    const auto append_address_rows =
        [&](const std::vector<AdvancedFlowFilterAddressEditorRow>& rows,
            const bool exclude,
            const QString& family_label) -> bool {
            for (std::size_t index = 0; index < rows.size(); ++index) {
                const auto& row = rows[index];
                const auto address_text = row.address_text.trimmed();
                const auto prefix_text = row.prefix_text.trimmed();
                if (!row.subnet_enabled) {
                    if (address_text.isEmpty()) {
                        continue;
                    }
                } else {
                    if (address_text.isEmpty() && prefix_text.isEmpty()) {
                        continue;
                    }
                    if (address_text.isEmpty() || prefix_text.isEmpty()) {
                        if (errorText != nullptr) {
                            *errorText = QStringLiteral("%1 row %2: Subnet rules require both Address and Prefix.")
                                .arg(family_label)
                                .arg(QString::number(index + 1U));
                        }
                        return false;
                    }
                }

                QHostAddress address {};
                if (!address.setAddress(address_text)) {
                    if (errorText != nullptr) {
                        *errorText = QStringLiteral("%1 row %2: Address must be a valid IPv4 or IPv6 value.")
                            .arg(family_label)
                            .arg(QString::number(index + 1U));
                    }
                    return false;
                }

                const auto protocol = address.protocol();
                if (protocol != QAbstractSocket::IPv4Protocol &&
                    protocol != QAbstractSocket::IPv6Protocol) {
                    if (errorText != nullptr) {
                        *errorText = QStringLiteral("%1 row %2: Address must be a valid IPv4 or IPv6 value.")
                            .arg(family_label)
                            .arg(QString::number(index + 1U));
                    }
                    return false;
                }

                if (!row.subnet_enabled) {
                    if (protocol == QAbstractSocket::IPv4Protocol) {
                        auto& target = exclude ? updated_addresses.ipv4_exclude : updated_addresses.ipv4_include;
                        target.push_back(session_detail::AdvancedFlowFilterIpv4AddressPredicate {
                            .match_kind = session_detail::AdvancedFlowFilterAddressMatchKind::exact,
                            .scope = row.scope,
                            .value = address.toIPv4Address(),
                            .prefix_length = 32U,
                        });
                    } else {
                        auto& target = exclude ? updated_addresses.ipv6_exclude : updated_addresses.ipv6_include;
                        target.push_back(session_detail::AdvancedFlowFilterIpv6AddressPredicate {
                            .match_kind = session_detail::AdvancedFlowFilterAddressMatchKind::exact,
                            .scope = row.scope,
                            .value = qhost_to_ipv6_bytes(address),
                            .prefix_length = 128U,
                        });
                    }
                    continue;
                }

                const auto prefix = parse_ui_u32_text(prefix_text);
                if (!prefix.has_value()) {
                    if (errorText != nullptr) {
                        *errorText = QStringLiteral("%1 row %2: Prefix must be an integer.")
                            .arg(family_label)
                            .arg(QString::number(index + 1U));
                    }
                    return false;
                }

                if (protocol == QAbstractSocket::IPv4Protocol) {
                    if (*prefix > 32U) {
                        if (errorText != nullptr) {
                            *errorText = QStringLiteral("%1 row %2: IPv4 prefix must be between 0 and 32.")
                                .arg(family_label)
                                .arg(QString::number(index + 1U));
                        }
                        return false;
                    }

                    auto& target = exclude ? updated_addresses.ipv4_exclude : updated_addresses.ipv4_include;
                    target.push_back(session_detail::AdvancedFlowFilterIpv4AddressPredicate {
                        .match_kind = session_detail::AdvancedFlowFilterAddressMatchKind::cidr,
                        .scope = row.scope,
                        .value = address.toIPv4Address(),
                        .prefix_length = static_cast<std::uint8_t>(*prefix),
                    });
                } else {
                    if (*prefix > 128U) {
                        if (errorText != nullptr) {
                            *errorText = QStringLiteral("%1 row %2: IPv6 prefix must be between 0 and 128.")
                                .arg(family_label)
                                .arg(QString::number(index + 1U));
                        }
                        return false;
                    }

                    auto& target = exclude ? updated_addresses.ipv6_exclude : updated_addresses.ipv6_include;
                    target.push_back(session_detail::AdvancedFlowFilterIpv6AddressPredicate {
                        .match_kind = session_detail::AdvancedFlowFilterAddressMatchKind::cidr,
                        .scope = row.scope,
                        .value = qhost_to_ipv6_bytes(address),
                        .prefix_length = static_cast<std::uint8_t>(*prefix),
                    });
                }
            }
            return true;
        };

    if (draft_document->section_states.ip_addresses) {
        updated_addresses = {};
        if (!append_address_rows(address_include_rows_, false, QStringLiteral("IP addresses include")) ||
            !append_address_rows(address_exclude_rows_, true, QStringLiteral("IP addresses exclude"))) {
            return false;
        }
    }

    auto updated_time = draft_document->configured_spec.time;
    const auto append_time_range_rows = [&](const QString& metric_id,
                                            const QString& label,
                                            const AdvancedFlowFilterTimeRangeEditorRow& row) -> bool {
        const auto from_text = row.from_text.trimmed();
        const auto to_text = row.to_text.trimmed();
        std::optional<session_detail::AdvancedFlowFilterInclusiveRange<std::uint64_t>>* target = nullptr;
        if (metric_id == QStringLiteral("start")) {
            target = &updated_time.start_us;
        } else if (metric_id == QStringLiteral("end")) {
            target = &updated_time.end_us;
        } else if (metric_id == QStringLiteral("overlap")) {
            target = &updated_time.overlap_us;
        }
        if (target == nullptr) {
            return false;
        }

        if (from_text.isEmpty() && to_text.isEmpty()) {
            target->reset();
            return true;
        }

        session_detail::AdvancedFlowFilterInclusiveRange<std::uint64_t> range {};
        const auto parse_bound = [&](const QString& text,
                                     const QString& field_label,
                                     std::optional<std::uint64_t>& out_value) -> bool {
            if (text.isEmpty()) {
                return true;
            }

            const auto parsed = session_detail::parse_advanced_flow_filter_utc_timestamp_text(text.toStdString());
            if (!parsed.ok) {
                if (errorText != nullptr) {
                    *errorText = QStringLiteral("%1 %2 must be a UTC timestamp in the form YYYY-MM-DDTHH:MM:SS(.ffffff)Z.")
                        .arg(label)
                        .arg(field_label);
                }
                return false;
            }

            out_value = parsed.value_us;
            return true;
        };

        if (!parse_bound(from_text, QStringLiteral("From"), range.min) ||
            !parse_bound(to_text, QStringLiteral("To"), range.max)) {
            return false;
        }

        if (range.min.has_value() && range.max.has_value() && *range.min > *range.max) {
            if (errorText != nullptr) {
                *errorText = QStringLiteral("%1 From must be less than or equal to To.").arg(label);
            }
            return false;
        }

        *target = range;
        return true;
    };

    auto updated_aggregate = draft_document->configured_spec.aggregate;
    const auto set_u64_range =
        [&](std::optional<session_detail::AdvancedFlowFilterInclusiveRange<std::uint64_t>>& target,
            const TrafficMetricDescriptor& descriptor,
            const AdvancedFlowFilterTrafficEditorRow& row) -> bool {
            const auto minimum_text = row.min_text.trimmed();
            const auto maximum_text = row.max_text.trimmed();
            if (minimum_text.isEmpty() && maximum_text.isEmpty()) {
                target.reset();
                return true;
            }

            session_detail::AdvancedFlowFilterInclusiveRange<std::uint64_t> range {};
            if (!minimum_text.isEmpty()) {
                const auto parsed_minimum = checked_parse_scaled_value<std::uint64_t>(
                    minimum_text,
                    traffic_metric_has_unit_selector(descriptor) ? traffic_unit_multiplier(row.unit) : 1ULL
                );
                if (!parsed_minimum.has_value()) {
                    if (errorText != nullptr) {
                        *errorText = QStringLiteral("%1 minimum must be a non-negative integer.")
                            .arg(QString::fromLatin1(descriptor.label));
                    }
                    return false;
                }
                range.min = *parsed_minimum;
            }

            if (!maximum_text.isEmpty()) {
                const auto parsed_maximum = checked_parse_scaled_value<std::uint64_t>(
                    maximum_text,
                    traffic_metric_has_unit_selector(descriptor) ? traffic_unit_multiplier(row.unit) : 1ULL
                );
                if (!parsed_maximum.has_value()) {
                    if (errorText != nullptr) {
                        *errorText = QStringLiteral("%1 maximum must be a non-negative integer.")
                            .arg(QString::fromLatin1(descriptor.label));
                    }
                    return false;
                }
                range.max = *parsed_maximum;
            }

            if (range.min.has_value() && range.max.has_value() && *range.min > *range.max) {
                if (errorText != nullptr) {
                    *errorText = QStringLiteral("%1 minimum must not exceed maximum.")
                        .arg(QString::fromLatin1(descriptor.label));
                }
                return false;
            }

            target = range;
            return true;
        };

    const auto set_u32_range =
        [&](std::optional<session_detail::AdvancedFlowFilterInclusiveRange<std::uint32_t>>& target,
            const TrafficMetricDescriptor& descriptor,
            const AdvancedFlowFilterTrafficEditorRow& row) -> bool {
            const auto minimum_text = row.min_text.trimmed();
            const auto maximum_text = row.max_text.trimmed();
            if (minimum_text.isEmpty() && maximum_text.isEmpty()) {
                target.reset();
                return true;
            }

            session_detail::AdvancedFlowFilterInclusiveRange<std::uint32_t> range {};
            if (!minimum_text.isEmpty()) {
                const auto parsed_minimum = checked_parse_scaled_value<std::uint32_t>(
                    minimum_text,
                    traffic_unit_multiplier(row.unit)
                );
                if (!parsed_minimum.has_value()) {
                    if (errorText != nullptr) {
                        *errorText = QStringLiteral("%1 minimum is too large.")
                            .arg(QString::fromLatin1(descriptor.label));
                    }
                    return false;
                }
                range.min = *parsed_minimum;
            }

            if (!maximum_text.isEmpty()) {
                const auto parsed_maximum = checked_parse_scaled_value<std::uint32_t>(
                    maximum_text,
                    traffic_unit_multiplier(row.unit)
                );
                if (!parsed_maximum.has_value()) {
                    if (errorText != nullptr) {
                        *errorText = QStringLiteral("%1 maximum is too large.")
                            .arg(QString::fromLatin1(descriptor.label));
                    }
                    return false;
                }
                range.max = *parsed_maximum;
            }

            if (range.min.has_value() && range.max.has_value() && *range.min > *range.max) {
                if (errorText != nullptr) {
                    *errorText = QStringLiteral("%1 minimum must not exceed maximum.")
                        .arg(QString::fromLatin1(descriptor.label));
                }
                return false;
            }

            target = range;
            return true;
        };

    if (draft_document->section_states.time) {
        updated_time = {};
        for (std::size_t index = 0; index < kTimeRangeDescriptors.size(); ++index) {
            const auto& descriptor = kTimeRangeDescriptors[index];
            if (!append_time_range_rows(
                    QString::fromLatin1(descriptor.metric_id),
                    QString::fromLatin1(descriptor.label),
                    time_range_rows_[index])) {
                return false;
            }
        }
        if (!set_u64_range(updated_time.duration_us, kTimeDurationDescriptor, time_duration_row_)) {
            return false;
        }
    }

    if (draft_document->section_states.traffic) {
        updated_aggregate = {};
        updated_aggregate.packet_distribution = draft_document->configured_spec.aggregate.packet_distribution;
        updated_aggregate.data_distribution = draft_document->configured_spec.aggregate.data_distribution;
        const auto apply_traffic_rows = [&](const auto& descriptors) -> bool {
            for (const auto& descriptor : descriptors) {
                const auto& row = traffic_rows_[static_cast<std::size_t>(descriptor.metric)];
                switch (descriptor.metric) {
                case AdvancedFlowFilterTrafficMetric::packet_count:
                    if (!set_u64_range(updated_aggregate.packet_count, descriptor, row)) {
                        return false;
                    }
                    break;
                case AdvancedFlowFilterTrafficMetric::original_bytes:
                    if (!set_u64_range(updated_aggregate.original_bytes, descriptor, row)) {
                        return false;
                    }
                    break;
                case AdvancedFlowFilterTrafficMetric::captured_bytes:
                    if (!set_u64_range(updated_aggregate.captured_bytes, descriptor, row)) {
                        return false;
                    }
                    break;
                case AdvancedFlowFilterTrafficMetric::a_to_b_packets:
                    if (!set_u64_range(updated_aggregate.a_to_b_packet_count, descriptor, row)) {
                        return false;
                    }
                    break;
                case AdvancedFlowFilterTrafficMetric::b_to_a_packets:
                    if (!set_u64_range(updated_aggregate.b_to_a_packet_count, descriptor, row)) {
                        return false;
                    }
                    break;
                case AdvancedFlowFilterTrafficMetric::a_to_b_original_bytes:
                    if (!set_u64_range(updated_aggregate.a_to_b_original_bytes, descriptor, row)) {
                        return false;
                    }
                    break;
                case AdvancedFlowFilterTrafficMetric::b_to_a_original_bytes:
                    if (!set_u64_range(updated_aggregate.b_to_a_original_bytes, descriptor, row)) {
                        return false;
                    }
                    break;
                case AdvancedFlowFilterTrafficMetric::max_original_packet_size:
                    if (!set_u32_range(updated_aggregate.max_original_packet_length, descriptor, row)) {
                        return false;
                    }
                    break;
                case AdvancedFlowFilterTrafficMetric::max_captured_packet_size:
                    if (!set_u32_range(updated_aggregate.max_captured_packet_length, descriptor, row)) {
                        return false;
                    }
                    break;
                case AdvancedFlowFilterTrafficMetric::fragmented_packet_count:
                    if (!set_u64_range(updated_aggregate.fragmented_packet_count, descriptor, row)) {
                        return false;
                    }
                    break;
                case AdvancedFlowFilterTrafficMetric::truncated_packet_count:
                    if (!set_u64_range(updated_aggregate.truncated_packet_count, descriptor, row)) {
                        return false;
                    }
                    break;
                case AdvancedFlowFilterTrafficMetric::tcp_syn_count:
                    if (!set_u64_range(updated_aggregate.tcp_syn_count, descriptor, row)) {
                        return false;
                    }
                    break;
                case AdvancedFlowFilterTrafficMetric::tcp_fin_count:
                    if (!set_u64_range(updated_aggregate.tcp_fin_count, descriptor, row)) {
                        return false;
                    }
                    break;
                case AdvancedFlowFilterTrafficMetric::tcp_rst_count:
                    if (!set_u64_range(updated_aggregate.tcp_rst_count, descriptor, row)) {
                        return false;
                    }
                    break;
                }
            }
            return true;
        };
        if (!apply_traffic_rows(kTrafficMetricDescriptors) ||
            !apply_traffic_rows(kDirectionalTrafficMetricDescriptors)) {
            return false;
        }
    }

    auto updated_service = draft_document->configured_spec.service;
    if (draft_document->section_states.service) {
        updated_service = {};
        if (service_include_known_) {
            updated_service.include.push_back({.kind = session_detail::AdvancedFlowFilterServicePredicateKind::known});
        }
        if (service_include_unknown_) {
            updated_service.include.push_back({.kind = session_detail::AdvancedFlowFilterServicePredicateKind::unknown});
        }
        if (service_exclude_known_) {
            updated_service.exclude.push_back({.kind = session_detail::AdvancedFlowFilterServicePredicateKind::known});
        }
        if (service_exclude_unknown_) {
            updated_service.exclude.push_back({.kind = session_detail::AdvancedFlowFilterServicePredicateKind::unknown});
        }

        const auto append_service_rows =
            [&](const std::vector<AdvancedFlowFilterServiceTextEditorRow>& rows,
                bool exclude) {
                auto& target = exclude ? updated_service.exclude : updated_service.include;
                for (const auto& row : rows) {
                    const auto trimmed = row.text.trimmed();
                    if (trimmed.isEmpty()) {
                        continue;
                    }
                    target.push_back(session_detail::AdvancedFlowFilterServicePredicate {
                        .kind = row.kind,
                        .value = trimmed.toStdString(),
                        .case_sensitivity = row.case_sensitive
                            ? session_detail::AdvancedFlowFilterStringCaseSensitivity::case_sensitive
                            : session_detail::AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive,
                    });
                }
            };

        append_service_rows(service_include_text_rows_, false);
        append_service_rows(service_exclude_text_rows_, true);
    }

    for (const auto& row : protocol_path_include_rows_) {
        updated_protocol_path.include.push_back(row.predicate);
    }
    for (const auto& row : protocol_path_exclude_rows_) {
        updated_protocol_path.exclude.push_back(row.predicate);
    }

    if (draft_document->section_states.contains_layer) {
        const auto append_contains_layer_rows =
            [&](const std::vector<AdvancedFlowFilterContainsLayerEditorRow>& rows,
                const bool exclude) -> bool {
                auto& target = exclude ? updated_protocol_path.exclude : updated_protocol_path.include;
                for (std::size_t index = 0; index < rows.size(); ++index) {
                    QString row_error {};
                    const auto predicate = contains_layer_predicate_from_editor_row(
                        rows[index],
                        &row_error,
                        QStringLiteral("Contains Layer %1 row %2")
                            .arg(exclude ? QStringLiteral("exclude") : QStringLiteral("include"))
                            .arg(QString::number(index + 1U))
                    );
                    if (!predicate.has_value()) {
                        if (errorText != nullptr) {
                            *errorText = row_error;
                        }
                        return false;
                    }
                    target.push_back(*predicate);
                }
                return true;
            };

        if (!append_contains_layer_rows(contains_layer_include_rows_, false) ||
            !append_contains_layer_rows(contains_layer_exclude_rows_, true)) {
            return false;
        }
    }

    draft_document->configured_spec.ports = std::move(updated_ports);
    draft_document->configured_spec.addresses = std::move(updated_addresses);
    draft_document->configured_spec.time = std::move(updated_time);
    draft_document->configured_spec.aggregate = std::move(updated_aggregate);
    draft_document->configured_spec.service = std::move(updated_service);
    draft_document->configured_spec.protocol_path = std::move(updated_protocol_path);
    return true;
}

void AdvancedFlowFilterEditorModel::setValidationText(const QString& text) {
    if (validation_text_ == text) {
        return;
    }

    validation_text_ = text;
    emit validationTextChanged();
    emit stateChanged();
}

void AdvancedFlowFilterEditorModel::ensureEditingInitialized() {
    document_state_.begin_edit();
    if (document_state_.is_editing() && !editing_initialized_) {
        initializeFromCurrentDocument();
    }
}

void AdvancedFlowFilterEditorModel::setHasUnsynchronizedBufferedChanges(const bool value) noexcept {
    if (has_unsynchronized_buffered_changes_ == value) {
        return;
    }

    has_unsynchronized_buffered_changes_ = value;
    emit hasUnsynchronizedBufferedChangesChanged();
}

void AdvancedFlowFilterEditorModel::clearValidationText() {
    if (validation_text_.isEmpty()) {
        return;
    }

    validation_text_.clear();
    emit validationTextChanged();
    emit stateChanged();
}

void AdvancedFlowFilterEditorModel::notifySectionSummaryChanged() {
    ++section_summary_revision_;
    emit sectionSummaryRevisionChanged();
}

void AdvancedFlowFilterEditorModel::notifyRowsChanged() {
    clearValidationText();
    notifyStateChanged();
}

void AdvancedFlowFilterEditorModel::notifyTextFieldEdited() {
    clearValidationText();
    notifySectionSummaryChanged();
    emit draftClearUnsavedChangesAvailableChanged();
    emit draftClearAllAvailableChanged();
    emit stateChanged();
}

void AdvancedFlowFilterEditorModel::notifyStateChanged() {
    ++revision_;
    emit revisionChanged();
    notifySectionSummaryChanged();
    emit draftClearUnsavedChangesAvailableChanged();
    emit draftClearAllAvailableChanged();
    emit stateChanged();
}

QVariantList AdvancedFlowFilterEditorModel::buildPortRowList(const bool exclude) const {
    const auto* rows = exclude ? &port_exclude_rows_ : &port_include_rows_;
    std::vector<AdvancedFlowFilterPortEditorRow> fallback_rows {};
    if (!document_state_.is_editing()) {
        const auto& predicates = exclude
            ? document_state_.current_user_visible_document().configured_spec.ports.exclude
            : document_state_.current_user_visible_document().configured_spec.ports.include;
        fallback_rows.reserve(predicates.size());
        for (const auto& predicate : predicates) {
            fallback_rows.push_back(AdvancedFlowFilterPortEditorRow {
                .scope = predicate.scope,
                .range_enabled = predicate.range.first != predicate.range.last,
                .primary_text = QString::number(predicate.range.first),
                .secondary_text = predicate.range.first == predicate.range.last
                    ? QString {}
                    : QString::number(predicate.range.last),
            });
        }
        rows = &fallback_rows;
    }

    QVariantList result {};
    result.reserve(static_cast<qsizetype>(rows->size()));
    for (std::size_t index = 0; index < rows->size(); ++index) {
        const auto& row = (*rows)[index];
        QVariantMap value {};
        value.insert(QStringLiteral("row"), static_cast<int>(index));
        value.insert(QStringLiteral("scope"), static_cast<int>(row.scope));
        value.insert(QStringLiteral("rangeEnabled"), row.range_enabled);
        value.insert(QStringLiteral("primaryText"), row.primary_text);
        value.insert(QStringLiteral("secondaryText"), row.secondary_text);
        result.push_back(value);
    }
    return result;
}

QVariantList AdvancedFlowFilterEditorModel::buildAddressRowList(const bool exclude) const {
    const auto* rows = exclude ? &address_exclude_rows_ : &address_include_rows_;
    std::vector<AdvancedFlowFilterAddressEditorRow> fallback_rows {};
    if (!document_state_.is_editing()) {
        const auto& addresses = document_state_.current_user_visible_document().configured_spec.addresses;
        const auto append_rows = [&](const auto& predicates) {
            for (const auto& predicate : predicates) {
                fallback_rows.push_back(AdvancedFlowFilterAddressEditorRow {
                    .scope = predicate.scope,
                    .subnet_enabled = predicate.match_kind == session_detail::AdvancedFlowFilterAddressMatchKind::cidr,
                    .address_text = [&]() {
                        if constexpr (std::is_same_v<std::decay_t<decltype(predicate.value)>, std::uint32_t>) {
                            return formatIpv4Address(predicate.value);
                        } else {
                            return formatIpv6Address(predicate.value);
                        }
                    }(),
                    .prefix_text = predicate.match_kind == session_detail::AdvancedFlowFilterAddressMatchKind::cidr
                        ? QString::number(predicate.prefix_length)
                        : QString {},
                });
            }
        };
        if (exclude) {
            append_rows(addresses.ipv4_exclude);
            append_rows(addresses.ipv6_exclude);
        } else {
            append_rows(addresses.ipv4_include);
            append_rows(addresses.ipv6_include);
        }
        rows = &fallback_rows;
    }

    QVariantList result {};
    result.reserve(static_cast<qsizetype>(rows->size()));
    for (std::size_t index = 0; index < rows->size(); ++index) {
        const auto& row = (*rows)[index];
        QVariantMap value {};
        value.insert(QStringLiteral("row"), static_cast<int>(index));
        value.insert(QStringLiteral("scope"), static_cast<int>(row.scope));
        value.insert(QStringLiteral("subnetEnabled"), row.subnet_enabled);
        value.insert(QStringLiteral("addressText"), row.address_text);
        value.insert(QStringLiteral("prefixText"), row.prefix_text);
        result.push_back(value);
    }
    return result;
}

QVariantList AdvancedFlowFilterEditorModel::buildTimeRangeRowList() const {
    std::vector<AdvancedFlowFilterTimeRangeEditorRow> fallback_rows {};
    const auto* rows = &time_range_rows_;
    if (!document_state_.is_editing() || !editing_initialized_) {
        fallback_rows.assign(kTimeRangeDescriptors.size(), {});
        for (std::size_t index = 0; index < kTimeRangeDescriptors.size(); ++index) {
            const auto& descriptor = kTimeRangeDescriptors[index];
            const auto range = time_range_u64(
                document_state_.current_user_visible_document().configured_spec.time,
                QString::fromLatin1(descriptor.metric_id)
            );
            auto& row = fallback_rows[index];
            row.from_text = range.has_value() && range->min.has_value()
                ? QString::fromStdString(
                    session_detail::format_advanced_flow_filter_utc_timestamp_text(*range->min).value_or(std::string {}))
                : QString {};
            row.to_text = range.has_value() && range->max.has_value()
                ? QString::fromStdString(
                    session_detail::format_advanced_flow_filter_utc_timestamp_text(*range->max).value_or(std::string {}))
                : QString {};
        }
        rows = &fallback_rows;
    }

    QVariantList result {};
    result.reserve(static_cast<qsizetype>(kTimeRangeDescriptors.size()));
    for (std::size_t index = 0; index < kTimeRangeDescriptors.size(); ++index) {
        const auto& descriptor = kTimeRangeDescriptors[index];
        const auto& row = (*rows)[index];
        QVariantMap value {};
        value.insert(QStringLiteral("metricId"), QString::fromLatin1(descriptor.metric_id));
        value.insert(QStringLiteral("label"), QString::fromLatin1(descriptor.label));
        value.insert(QStringLiteral("objectNamePrefix"), QString::fromLatin1(descriptor.object_name_prefix));
        value.insert(QStringLiteral("fromText"), row.from_text);
        value.insert(QStringLiteral("toText"), row.to_text);
        result.push_back(value);
    }
    return result;
}

QVariantMap AdvancedFlowFilterEditorModel::buildTimeDurationRow() const {
    auto row = time_duration_row_;
    if (!document_state_.is_editing() || !editing_initialized_) {
        const auto range = load_u64_range(document_state_.current_user_visible_document().configured_spec.time.duration_us);
        row.unit = choose_largest_exact_unit(
            kTimeDurationDescriptor,
            range.has_value() ? range->min : std::nullopt,
            range.has_value() ? range->max : std::nullopt
        );
        row.min_text = format_scaled_integer_text(range.has_value() ? range->min : std::nullopt, row.unit);
        row.max_text = format_scaled_integer_text(range.has_value() ? range->max : std::nullopt, row.unit);
    }

    QVariantMap value {};
    value.insert(QStringLiteral("metricId"), QStringLiteral("duration"));
    value.insert(QStringLiteral("label"), QString::fromLatin1(kTimeDurationDescriptor.label));
    value.insert(QStringLiteral("objectNamePrefix"), QString::fromLatin1(kTimeDurationDescriptor.object_name_prefix));
    value.insert(QStringLiteral("minText"), row.min_text);
    value.insert(QStringLiteral("maxText"), row.max_text);
    value.insert(QStringLiteral("hasUnitSelector"), true);
    value.insert(QStringLiteral("unitText"), QString {});
    value.insert(QStringLiteral("unitOptions"), traffic_metric_unit_options(kTimeDurationDescriptor));
    value.insert(QStringLiteral("selectedUnit"), static_cast<int>(row.unit));
    return value;
}

QVariantList AdvancedFlowFilterEditorModel::buildTrafficRowList(const TrafficRowGroup group) const {
    std::vector<AdvancedFlowFilterTrafficEditorRow> fallback_rows {};
    const auto* rows = &traffic_rows_;
    if (!document_state_.is_editing() || !editing_initialized_) {
        fallback_rows.assign(
            static_cast<std::size_t>(AdvancedFlowFilterTrafficMetric::b_to_a_original_bytes) + 1U,
            {}
        );
        const auto initialize_rows = [&](const auto& descriptors) {
            for (const auto& descriptor : descriptors) {
                const auto range = traffic_metric_range_u64(
                    document_state_.current_user_visible_document().configured_spec.aggregate,
                    descriptor.metric
                );
                const auto unit = choose_largest_exact_unit(
                    descriptor,
                    range.has_value() ? range->min : std::nullopt,
                    range.has_value() ? range->max : std::nullopt
                );
                auto& row = fallback_rows[static_cast<std::size_t>(descriptor.metric)];
                row.unit = unit;
                row.min_text = format_scaled_integer_text(range.has_value() ? range->min : std::nullopt, unit);
                row.max_text = format_scaled_integer_text(range.has_value() ? range->max : std::nullopt, unit);
            }
        };
        initialize_rows(kTrafficMetricDescriptors);
        initialize_rows(kDirectionalTrafficMetricDescriptors);
        rows = &fallback_rows;
    }

    QVariantList result {};
    const auto append_rows = [&](const auto& descriptors) {
        for (const auto& descriptor : descriptors) {
            if (descriptor.group != group) {
                continue;
            }

            const auto& row = (*rows)[static_cast<std::size_t>(descriptor.metric)];
            QVariantMap value {};
            value.insert(QStringLiteral("metricId"), static_cast<int>(descriptor.metric));
            value.insert(QStringLiteral("label"), QString::fromLatin1(descriptor.label));
            value.insert(QStringLiteral("objectNamePrefix"), QString::fromLatin1(descriptor.object_name_prefix));
            value.insert(QStringLiteral("minText"), row.min_text);
            value.insert(QStringLiteral("maxText"), row.max_text);
            value.insert(QStringLiteral("hasUnitSelector"), traffic_metric_has_unit_selector(descriptor));
            value.insert(QStringLiteral("unitText"), traffic_metric_static_unit_text(descriptor));
            value.insert(QStringLiteral("unitOptions"), traffic_metric_unit_options(descriptor));
            value.insert(QStringLiteral("selectedUnit"), static_cast<int>(row.unit));
            result.push_back(value);
        }
    };
    append_rows(kTrafficMetricDescriptors);
    append_rows(kDirectionalTrafficMetricDescriptors);
    return result;
}

QVariantList AdvancedFlowFilterEditorModel::buildServiceTextRowList(const bool exclude) const {
    std::vector<AdvancedFlowFilterServiceTextEditorRow> fallback_rows {};
    const auto* rows = exclude ? &service_exclude_text_rows_ : &service_include_text_rows_;
    if (!document_state_.is_editing() || !editing_initialized_) {
        const auto& predicates = exclude
            ? document_state_.current_user_visible_document().configured_spec.service.exclude
            : document_state_.current_user_visible_document().configured_spec.service.include;
        for (const auto& predicate : predicates) {
            if (service_kind_is_state(predicate.kind)) {
                continue;
            }
            fallback_rows.push_back(AdvancedFlowFilterServiceTextEditorRow {
                .kind = predicate.kind,
                .case_sensitive = predicate.case_sensitivity ==
                    session_detail::AdvancedFlowFilterStringCaseSensitivity::case_sensitive,
                .text = QString::fromStdString(predicate.value),
            });
        }
        rows = &fallback_rows;
    }

    QVariantList result {};
    result.reserve(static_cast<qsizetype>(rows->size()));
    for (std::size_t index = 0; index < rows->size(); ++index) {
        const auto& row = (*rows)[index];
        QVariantMap value {};
        value.insert(QStringLiteral("row"), static_cast<int>(index));
        value.insert(QStringLiteral("kind"), static_cast<int>(row.kind));
        value.insert(QStringLiteral("caseSensitive"), row.case_sensitive);
        value.insert(QStringLiteral("text"), row.text);
        result.push_back(value);
    }
    return result;
}

QVariantList AdvancedFlowFilterEditorModel::buildProtocolPathRowList(const bool exclude) const {
    std::vector<AdvancedFlowFilterProtocolPathEditorRow> fallback_rows {};
    const auto* rows = exclude ? &protocol_path_exclude_rows_ : &protocol_path_include_rows_;
    if (!document_state_.is_editing() || !editing_initialized_) {
        const auto& predicates = exclude
            ? document_state_.current_user_visible_document().configured_spec.protocol_path.exclude
            : document_state_.current_user_visible_document().configured_spec.protocol_path.include;
        for (const auto& predicate : predicates) {
            if (!protocol_path_predicate_is_ui_managed(predicate)) {
                continue;
            }

            fallback_rows.push_back(AdvancedFlowFilterProtocolPathEditorRow {
                .predicate = predicate,
                .selector_mode = protocol_path_selector_mode_from_predicate(predicate),
                .applicable = protocol_path_applicability_resolver_
                    ? protocol_path_applicability_resolver_(predicate)
                    : std::nullopt,
            });
        }
        rows = &fallback_rows;
    }

    QVariantList result {};
    result.reserve(static_cast<qsizetype>(rows->size()));
    for (std::size_t index = 0; index < rows->size(); ++index) {
        const auto& row = (*rows)[index];
        QVariantMap value {};
        value.insert(QStringLiteral("row"), static_cast<int>(index));
        value.insert(QStringLiteral("mode"), static_cast<int>(row.selector_mode));
        value.insert(QStringLiteral("modeLabel"), protocol_path_selector_mode_label(row.selector_mode));
        value.insert(QStringLiteral("compactText"), protocol_path_compact_display_text(row.predicate.layers));
        value.insert(QStringLiteral("fullText"), protocol_path_full_display_text(row.predicate.layers));
        value.insert(QStringLiteral("applicabilityKnown"), row.applicable.has_value());
        value.insert(QStringLiteral("applicable"), row.applicable.value_or(false));
        value.insert(
            QStringLiteral("statusText"),
            !row.applicable.has_value()
                ? QStringLiteral("No current capture.")
                : (row.applicable.value()
                    ? QString {}
                    : QStringLiteral("Not present in current capture"))
        );
        result.push_back(value);
    }
    return result;
}

QVariantList AdvancedFlowFilterEditorModel::buildContainsLayerRowList(const bool exclude) const {
    std::vector<AdvancedFlowFilterContainsLayerEditorRow> fallback_rows {};
    const auto* rows = exclude ? &contains_layer_exclude_rows_ : &contains_layer_include_rows_;
    if (!document_state_.is_editing() || !editing_initialized_) {
        const auto& predicates = exclude
            ? document_state_.current_user_visible_document().configured_spec.protocol_path.exclude
            : document_state_.current_user_visible_document().configured_spec.protocol_path.include;
        for (const auto& predicate : predicates) {
            if (!contains_layer_predicate_is_ui_managed(predicate) || predicate.layers.size() != 1U) {
                continue;
            }

            const auto& layer = predicate.layers.front();
            const auto* descriptor = session_detail::protocol_path_contains_layer_descriptor(layer.kind);
            if (descriptor == nullptr) {
                continue;
            }

            fallback_rows.push_back(AdvancedFlowFilterContainsLayerEditorRow {
                .kind = descriptor->kind,
                .identifier_mode = layer.identifier.has_value()
                    ? AdvancedFlowFilterContainsLayerIdentifierMode::exact
                    : AdvancedFlowFilterContainsLayerIdentifierMode::any,
                .exact_value_text = layer.identifier.has_value()
                    ? QString::fromStdString(session_detail::format_protocol_path_identifier_editor_text(
                          layer.identifier->kind,
                          layer.identifier->value
                      ))
                    : QString {},
                .applicable = protocol_path_applicability_resolver_
                    ? protocol_path_applicability_resolver_(predicate)
                    : std::nullopt,
            });
        }
        rows = &fallback_rows;
    }

    QVariantList result {};
    result.reserve(static_cast<qsizetype>(rows->size()));
    for (std::size_t index = 0; index < rows->size(); ++index) {
        const auto& row = (*rows)[index];
        const auto* descriptor = session_detail::protocol_path_contains_layer_descriptor(row.kind);
        if (descriptor == nullptr) {
            continue;
        }

        bool predicate_valid = false;
        const auto applicability = contains_layer_row_applicability(
            row,
            protocol_path_applicability_resolver_,
            &predicate_valid
        );

        QVariantMap value {};
        value.insert(QStringLiteral("row"), static_cast<int>(index));
        value.insert(QStringLiteral("layerKind"), static_cast<int>(descriptor->kind));
        value.insert(QStringLiteral("layerLabel"), QString::fromLatin1(descriptor->layer_label));
        value.insert(QStringLiteral("layerObjectNameSuffix"), QString::fromLatin1(descriptor->object_name_suffix));
        value.insert(QStringLiteral("identifierLabel"), QString::fromLatin1(descriptor->identifier_label));
        value.insert(QStringLiteral("identifierMode"), static_cast<int>(row.identifier_mode));
        value.insert(QStringLiteral("exactValueText"), row.exact_value_text);
        value.insert(QStringLiteral("exactValuePlaceholder"), contains_layer_exact_placeholder_text(*descriptor));
        value.insert(
            QStringLiteral("preferredInputFormat"),
            static_cast<int>(descriptor->preferred_input_format)
        );
        value.insert(
            QStringLiteral("compactText"),
            contains_layer_compact_text(*descriptor, row.identifier_mode, row.exact_value_text)
        );
        value.insert(QStringLiteral("applicabilityKnown"), predicate_valid && applicability.has_value());
        value.insert(QStringLiteral("applicable"), predicate_valid && applicability.value_or(false));
        value.insert(
            QStringLiteral("statusText"),
            !predicate_valid
                ? QString {}
                : (!applicability.has_value()
                    ? QStringLiteral("No current capture.")
                    : (applicability.value()
                        ? QString {}
                        : QStringLiteral("Not present in current capture")))
        );
        result.push_back(value);
    }
    return result;
}

}  // namespace pfl
