#include "ui/app/FlowListModel.h"

#include <QStringList>

#include <algorithm>
#include <variant>

namespace pfl {

namespace {

QString format_protocol(const ProtocolId protocol) {
    switch (protocol) {
    case ProtocolId::arp:
        return "ARP";
    case ProtocolId::icmp:
        return "ICMP";
    case ProtocolId::tcp:
        return "TCP";
    case ProtocolId::udp:
        return "UDP";
    case ProtocolId::icmpv6:
        return "ICMPv6";
    default:
        return "unknown";
    }
}

QString format_ipv4_address(const std::uint32_t address) {
    return QStringLiteral("%1.%2.%3.%4")
        .arg((address >> 24U) & 0xFFU)
        .arg((address >> 16U) & 0xFFU)
        .arg((address >> 8U) & 0xFFU)
        .arg(address & 0xFFU);
}

QString format_ipv6_address(const std::array<std::uint8_t, 16>& address) {
    QStringList parts {};
    parts.reserve(8);

    for (std::size_t index = 0; index < 8; ++index) {
        const auto word = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(address[index * 2U]) << 8U) |
            static_cast<std::uint16_t>(address[index * 2U + 1U])
        );
        parts.push_back(QStringLiteral("%1").arg(word, 4, 16, QChar('0')));
    }

    return parts.join(QStringLiteral(":"));
}

QString format_endpoint(const EndpointKeyV4& endpoint) {
    return QStringLiteral("%1:%2")
        .arg(format_ipv4_address(endpoint.addr))
        .arg(endpoint.port);
}

QString format_endpoint(const EndpointKeyV6& endpoint) {
    return QStringLiteral("[%1]:%2")
        .arg(format_ipv6_address(endpoint.addr))
        .arg(endpoint.port);
}

bool contains_text(const FlowListModel::Item& item, const QString& filter) {
    return item.family.contains(filter, Qt::CaseInsensitive)
        || item.protocol.contains(filter, Qt::CaseInsensitive)
        || item.endpoint_a.contains(filter, Qt::CaseInsensitive)
        || item.endpoint_b.contains(filter, Qt::CaseInsensitive);
}

bool less_than(const FlowListModel::Item& left, const FlowListModel::Item& right, const FlowListModel::SortKey key) {
    switch (key) {
    case FlowListModel::SortKey::index:
        return left.flow_index < right.flow_index;
    case FlowListModel::SortKey::family:
        return left.family < right.family;
    case FlowListModel::SortKey::protocol:
        return left.protocol < right.protocol;
    case FlowListModel::SortKey::endpoint_a:
        return left.endpoint_a < right.endpoint_a;
    case FlowListModel::SortKey::endpoint_b:
        return left.endpoint_b < right.endpoint_b;
    case FlowListModel::SortKey::packets:
        if (left.packets != right.packets) {
            return left.packets < right.packets;
        }
        return left.flow_index < right.flow_index;
    case FlowListModel::SortKey::bytes:
        if (left.bytes != right.bytes) {
            return left.bytes < right.bytes;
        }
        return left.flow_index < right.flow_index;
    }

    return left.flow_index < right.flow_index;
}

}  // namespace

FlowListModel::FlowListModel(QObject* parent)
    : QAbstractListModel(parent) {
}

int FlowListModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid()) {
        return 0;
    }

    return static_cast<int>(visible_items_.size());
}

QVariant FlowListModel::data(const QModelIndex& index, const int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= rowCount()) {
        return {};
    }

    const Item& item = visible_items_[static_cast<std::size_t>(index.row())];
    switch (role) {
    case FlowIndexRole:
        return item.flow_index;
    case FamilyRole:
        return item.family;
    case ProtocolRole:
        return item.protocol;
    case EndpointARole:
        return item.endpoint_a;
    case EndpointBRole:
        return item.endpoint_b;
    case PacketsRole:
        return QString::number(item.packets);
    case BytesRole:
        return QString::number(item.bytes);
    default:
        return {};
    }
}

QHash<int, QByteArray> FlowListModel::roleNames() const {
    return {
        {FlowIndexRole, "flowIndex"},
        {FamilyRole, "family"},
        {ProtocolRole, "protocol"},
        {EndpointARole, "endpointA"},
        {EndpointBRole, "endpointB"},
        {PacketsRole, "packets"},
        {BytesRole, "bytes"},
    };
}

int FlowListModel::rowForFlowIndex(const int flowIndex) const noexcept {
    for (std::size_t row = 0; row < visible_items_.size(); ++row) {
        if (visible_items_[row].flow_index == flowIndex) {
            return static_cast<int>(row);
        }
    }

    return -1;
}

void FlowListModel::refresh(const std::vector<FlowRow>& rows) {
    all_items_.clear();
    all_items_.reserve(rows.size());

    for (const auto& row : rows) {
        Item item {};
        item.flow_index = static_cast<int>(row.index);
        item.packets = static_cast<qulonglong>(row.packet_count);
        item.bytes = static_cast<qulonglong>(row.total_bytes);

        if (row.family == FlowAddressFamily::ipv4) {
            const auto& key = std::get<ConnectionKeyV4>(row.key);
            item.family = "IPv4";
            item.protocol = format_protocol(key.protocol);
            item.endpoint_a = format_endpoint(key.first);
            item.endpoint_b = format_endpoint(key.second);
        } else {
            const auto& key = std::get<ConnectionKeyV6>(row.key);
            item.family = "IPv6";
            item.protocol = format_protocol(key.protocol);
            item.endpoint_a = format_endpoint(key.first);
            item.endpoint_b = format_endpoint(key.second);
        }

        all_items_.push_back(std::move(item));
    }

    rebuildVisibleItems();
}

void FlowListModel::clear() {
    all_items_.clear();
    rebuildVisibleItems();
}

void FlowListModel::resetViewState() {
    filter_text_.clear();
    sort_key_ = SortKey::index;
    sort_ascending_ = true;
    rebuildVisibleItems();
}

void FlowListModel::setFilterText(const QString& text) {
    if (filter_text_ == text) {
        return;
    }

    filter_text_ = text;
    rebuildVisibleItems();
}

void FlowListModel::setSortKey(const SortKey key) {
    if (sort_key_ == key) {
        return;
    }

    sort_key_ = key;
    rebuildVisibleItems();
}

void FlowListModel::setSortAscending(const bool ascending) noexcept {
    if (sort_ascending_ == ascending) {
        return;
    }

    sort_ascending_ = ascending;
    rebuildVisibleItems();
}

const QString& FlowListModel::filterText() const noexcept {
    return filter_text_;
}

FlowListModel::SortKey FlowListModel::sortKey() const noexcept {
    return sort_key_;
}

bool FlowListModel::sortAscending() const noexcept {
    return sort_ascending_;
}

bool FlowListModel::containsFlowIndex(const int flowIndex) const noexcept {
    return std::any_of(visible_items_.begin(), visible_items_.end(), [flowIndex](const Item& item) {
        return item.flow_index == flowIndex;
    });
}

void FlowListModel::rebuildVisibleItems() {
    beginResetModel();
    visible_items_.clear();
    visible_items_.reserve(all_items_.size());

    for (const auto& item : all_items_) {
        if (filter_text_.isEmpty() || contains_text(item, filter_text_)) {
            visible_items_.push_back(item);
        }
    }

    std::sort(visible_items_.begin(), visible_items_.end(), [this](const Item& left, const Item& right) {
        const bool isLess = less_than(left, right, sort_key_);
        const bool isGreater = less_than(right, left, sort_key_);

        if (!isLess && !isGreater) {
            return left.flow_index < right.flow_index;
        }

        return sort_ascending_ ? isLess : isGreater;
    });

    endResetModel();
}

}  // namespace pfl
