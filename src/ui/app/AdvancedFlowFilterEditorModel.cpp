#include "ui/app/AdvancedFlowFilterEditorModel.h"

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
        {session_detail::AdvancedFlowFilterDirectionality::unidirectional, "One direction", "Unidirectional"},
        {session_detail::AdvancedFlowFilterDirectionality::bidirectional, "Both directions", "Bidirectional"},
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
    bool additional {false};
    TrafficMetricValueKind value_kind {TrafficMetricValueKind::count};
};

constexpr std::array<TrafficMetricDescriptor, 11> kTrafficMetricDescriptors {{
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::packet_count,
     "Packets",
     "PacketCount",
     false,
     TrafficMetricValueKind::count},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::original_bytes,
     "Original bytes",
     "OriginalBytes",
     false,
     TrafficMetricValueKind::bytes_u64},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::captured_bytes,
     "Captured bytes",
     "CapturedBytes",
     false,
     TrafficMetricValueKind::bytes_u64},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::duration,
     "Duration",
     "Duration",
     false,
     TrafficMetricValueKind::duration_us},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::max_original_packet_size,
     "Maximum original packet size",
     "MaxOriginalPacketSize",
     true,
     TrafficMetricValueKind::bytes_u32},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::max_captured_packet_size,
     "Maximum captured packet size",
     "MaxCapturedPacketSize",
     true,
     TrafficMetricValueKind::bytes_u32},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::fragmented_packet_count,
     "Fragmented packet count",
     "FragmentedPacketCount",
     true,
     TrafficMetricValueKind::count},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::truncated_packet_count,
     "Truncated packet count",
     "TruncatedPacketCount",
     true,
     TrafficMetricValueKind::count},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::tcp_syn_count,
     "TCP SYN count",
     "TcpSynCount",
     true,
     TrafficMetricValueKind::count},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::tcp_fin_count,
     "TCP FIN count",
     "TcpFinCount",
     true,
     TrafficMetricValueKind::count},
    {AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric::tcp_rst_count,
     "TCP RST count",
     "TcpRstCount",
     true,
     TrafficMetricValueKind::count},
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
    const auto index = static_cast<std::size_t>(metric);
    return index < kTrafficMetricDescriptors.size() ? &kTrafficMetricDescriptors[index] : nullptr;
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
    if (traffic_metric_uses_byte_units(descriptor)) {
        return build_advanced_filter_static_option_list(kAdvancedFlowFilterByteUnitOptions);
    }
    if (traffic_metric_uses_duration_units(descriptor)) {
        return build_advanced_filter_static_option_list(kAdvancedFlowFilterDurationUnitOptions);
    }
    return {};
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
    if (traffic_metric_uses_byte_units(descriptor)) {
        return unit == AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::bytes ||
            unit == AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::kib ||
            unit == AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::mib ||
            unit == AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::gib ||
            unit == AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::tib;
    }
    if (traffic_metric_uses_duration_units(descriptor)) {
        return unit == AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::microseconds ||
            unit == AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::milliseconds ||
            unit == AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::seconds ||
            unit == AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::minutes ||
            unit == AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit::hours;
    }
    return false;
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
    case Metric::duration:
        return load_u64_range(aggregate.duration_us);
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

bool any_additional_traffic_metric_active(const session_detail::AdvancedFlowFilterAggregateCriteria& aggregate) {
    for (const auto& descriptor : kTrafficMetricDescriptors) {
        if (!descriptor.additional) {
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

std::array<std::uint8_t, 16> qhost_to_ipv6_bytes(const QHostAddress& address) {
    const auto ipv6 = address.toIPv6Address();
    std::array<std::uint8_t, 16> bytes {};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = ipv6[static_cast<int>(index)];
    }
    return bytes;
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
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::traffic:
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::service:
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
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::traffic:
        return states.traffic;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::service:
        return states.service;
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
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::traffic:
        return &states.traffic;
    case AdvancedFlowFilterEditorModel::AdvancedFlowFilterFiniteSection::service:
        return &states.service;
    }

    return nullptr;
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

QString AdvancedFlowFilterEditorModel::validationText() const {
    return validation_text_;
}

bool AdvancedFlowFilterEditorModel::draftClearAllAvailable() const noexcept {
    return false;
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
    }

    return false;
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
    case AdvancedFlowFilterFiniteSection::traffic:
    case AdvancedFlowFilterFiniteSection::service:
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
    case AdvancedFlowFilterFiniteSection::traffic:
    case AdvancedFlowFilterFiniteSection::service:
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

QVariantList AdvancedFlowFilterEditorModel::commonTrafficRows() const {
    return buildTrafficRowList(false);
}

QVariantList AdvancedFlowFilterEditorModel::additionalTrafficRows() const {
    return buildTrafficRowList(true);
}

bool AdvancedFlowFilterEditorModel::trafficAdditionalFiltersExpandedSuggested() const noexcept {
    if (document_state_.is_editing()) {
        auto* draft_document = document_state_.draft_document();
        return draft_document != nullptr &&
            any_additional_traffic_metric_active(draft_document->configured_spec.aggregate);
    }
    return any_additional_traffic_metric_active(document_state_.current_user_visible_document().configured_spec.aggregate);
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

QVariantList AdvancedFlowFilterEditorModel::serviceOperatorOptions() const {
    return build_advanced_filter_static_option_list(kAdvancedFlowFilterServiceOperatorOptions);
}

QVariantList AdvancedFlowFilterEditorModel::serviceTextRows(const bool exclude) const {
    return buildServiceTextRowList(exclude);
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
    case AdvancedFlowFilterFiniteSection::traffic:
    case AdvancedFlowFilterFiniteSection::service:
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

void AdvancedFlowFilterEditorModel::initializeFromCurrentDocument() {
    const auto& document = document_state_.current_user_visible_document();
    port_include_rows_.clear();
    port_exclude_rows_.clear();
    address_include_rows_.clear();
    address_exclude_rows_.clear();
    traffic_rows_.assign(kTrafficMetricDescriptors.size(), {});
    service_include_known_ = false;
    service_include_unknown_ = false;
    service_exclude_known_ = false;
    service_exclude_unknown_ = false;
    service_include_text_rows_.clear();
    service_exclude_text_rows_.clear();

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

    for (const auto& descriptor : kTrafficMetricDescriptors) {
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

    editing_initialized_ = true;
    clearValidationText();
    notifyStateChanged();
}

void AdvancedFlowFilterEditorModel::clearTransientState() noexcept {
    port_include_rows_.clear();
    port_exclude_rows_.clear();
    address_include_rows_.clear();
    address_exclude_rows_.clear();
    traffic_rows_.clear();
    service_include_known_ = false;
    service_include_unknown_ = false;
    service_exclude_known_ = false;
    service_exclude_unknown_ = false;
    service_include_text_rows_.clear();
    service_exclude_text_rows_.clear();
    editing_initialized_ = false;
    validation_text_.clear();
    notifyStateChanged();
}

bool AdvancedFlowFilterEditorModel::synchronizeDraftSections(QString* errorText) {
    auto* draft_document = document_state_.draft_document();
    if (draft_document == nullptr) {
        if (errorText != nullptr) {
            *errorText = QStringLiteral("Advanced Filter draft is unavailable.");
        }
        return false;
    }

    auto updated_ports = draft_document->configured_spec.ports;
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

    if (draft_document->section_states.traffic) {
        updated_aggregate = {};
        for (const auto& descriptor : kTrafficMetricDescriptors) {
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
            case AdvancedFlowFilterTrafficMetric::duration:
                if (!set_u64_range(updated_aggregate.duration_us, descriptor, row)) {
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

    draft_document->configured_spec.ports = std::move(updated_ports);
    draft_document->configured_spec.addresses = std::move(updated_addresses);
    draft_document->configured_spec.aggregate = std::move(updated_aggregate);
    draft_document->configured_spec.service = std::move(updated_service);
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

void AdvancedFlowFilterEditorModel::clearValidationText() {
    if (validation_text_.isEmpty()) {
        return;
    }

    validation_text_.clear();
    emit validationTextChanged();
    emit stateChanged();
}

void AdvancedFlowFilterEditorModel::notifyRowsChanged() {
    clearValidationText();
    notifyStateChanged();
}

void AdvancedFlowFilterEditorModel::notifyTextFieldEdited() {
    clearValidationText();
    emit draftClearAllAvailableChanged();
    emit stateChanged();
}

void AdvancedFlowFilterEditorModel::notifyStateChanged() {
    ++revision_;
    emit revisionChanged();
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

QVariantList AdvancedFlowFilterEditorModel::buildTrafficRowList(const bool additional) const {
    std::vector<AdvancedFlowFilterTrafficEditorRow> fallback_rows {};
    const auto* rows = &traffic_rows_;
    if (!document_state_.is_editing() || !editing_initialized_) {
        fallback_rows.assign(kTrafficMetricDescriptors.size(), {});
        for (const auto& descriptor : kTrafficMetricDescriptors) {
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
        rows = &fallback_rows;
    }

    QVariantList result {};
    for (const auto& descriptor : kTrafficMetricDescriptors) {
        if (descriptor.additional != additional) {
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
        value.insert(QStringLiteral("additional"), descriptor.additional);
        result.push_back(value);
    }
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

}  // namespace pfl
