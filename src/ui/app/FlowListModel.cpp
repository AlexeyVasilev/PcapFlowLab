#include "ui/app/FlowListModel.h"

#include <QStringList>

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

}  // namespace

FlowListModel::FlowListModel(QObject* parent)
    : QAbstractListModel(parent) {
}

int FlowListModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid()) {
        return 0;
    }

    return static_cast<int>(items_.size());
}

QVariant FlowListModel::data(const QModelIndex& index, const int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= rowCount()) {
        return {};
    }

    const Item& item = items_[static_cast<std::size_t>(index.row())];
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

void FlowListModel::refresh(const std::vector<FlowRow>& rows) {
    beginResetModel();
    items_.clear();
    items_.reserve(rows.size());

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

        items_.push_back(std::move(item));
    }

    endResetModel();
}

void FlowListModel::clear() {
    refresh({});
}

}  // namespace pfl

