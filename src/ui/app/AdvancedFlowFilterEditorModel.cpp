#include "ui/app/AdvancedFlowFilterEditorModel.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
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
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::setPortRowSecondaryText(const bool exclude, const int row, const QString& text) {
    auto& rows = exclude ? port_exclude_rows_ : port_include_rows_;
    if (row < 0 || static_cast<std::size_t>(row) >= rows.size()) {
        return;
    }

    rows[static_cast<std::size_t>(row)].secondary_text = text;
    (void)synchronizeDraftSections();
    notifyRowsChanged();
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
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::setAddressRowPrefixText(const bool exclude, const int row, const QString& text) {
    auto& rows = exclude ? address_exclude_rows_ : address_include_rows_;
    if (row < 0 || static_cast<std::size_t>(row) >= rows.size()) {
        return;
    }

    rows[static_cast<std::size_t>(row)].prefix_text = text;
    (void)synchronizeDraftSections();
    notifyRowsChanged();
}

void AdvancedFlowFilterEditorModel::initializeFromCurrentDocument() {
    const auto& document = document_state_.current_user_visible_document();
    port_include_rows_.clear();
    port_exclude_rows_.clear();
    address_include_rows_.clear();
    address_exclude_rows_.clear();

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
    clearValidationText();
    notifyStateChanged();
}

void AdvancedFlowFilterEditorModel::clearTransientState() noexcept {
    port_include_rows_.clear();
    port_exclude_rows_.clear();
    address_include_rows_.clear();
    address_exclude_rows_.clear();
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

    draft_document->configured_spec.ports = std::move(updated_ports);
    draft_document->configured_spec.addresses = std::move(updated_addresses);
    return true;
}

void AdvancedFlowFilterEditorModel::setValidationText(const QString& text) {
    if (validation_text_ == text) {
        return;
    }

    validation_text_ = text;
    notifyStateChanged();
}

bool AdvancedFlowFilterEditorModel::hasTransientEditorRows() const noexcept {
    return !port_include_rows_.empty() ||
        !port_exclude_rows_.empty() ||
        !address_include_rows_.empty() ||
        !address_exclude_rows_.empty();
}

void AdvancedFlowFilterEditorModel::ensureEditingInitialized() {
    document_state_.begin_edit();
    if (document_state_.is_editing() && !hasTransientEditorRows()) {
        initializeFromCurrentDocument();
    }
}

void AdvancedFlowFilterEditorModel::clearValidationText() {
    validation_text_.clear();
}

void AdvancedFlowFilterEditorModel::notifyRowsChanged() {
    clearValidationText();
    notifyStateChanged();
}

void AdvancedFlowFilterEditorModel::notifyStateChanged() {
    ++revision_;
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

}  // namespace pfl
