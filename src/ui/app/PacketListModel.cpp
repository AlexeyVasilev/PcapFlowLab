#include "ui/app/PacketListModel.h"

#include <algorithm>

namespace pfl {

PacketListModel::PacketListModel(QObject* parent)
    : QAbstractListModel(parent) {
}

int PacketListModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid()) {
        return 0;
    }

    return static_cast<int>(items_.size());
}

QVariant PacketListModel::data(const QModelIndex& index, const int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= rowCount()) {
        return {};
    }

    const Item& item = items_[static_cast<std::size_t>(index.row())];
    switch (role) {
    case RowNumberRole:
        return QVariant::fromValue(item.row_number);
    case PacketIndexRole:
        return QVariant::fromValue(item.packet_index);
    case DirectionTextRole:
        return item.direction_text;
    case TimestampRole:
        return item.timestamp;
    case CapturedLengthRole:
        return item.captured_length;
    case OriginalLengthRole:
        return item.original_length;
    case PayloadLengthRole:
        return item.payload_length;
    case IsIpFragmentedRole:
        return item.is_ip_fragmented;
    case SuspectedTcpRetransmissionRole:
        return item.suspected_tcp_retransmission;
    case TcpFlagsTextRole:
        return item.tcp_flags_text;
    default:
        return {};
    }
}

QHash<int, QByteArray> PacketListModel::roleNames() const {
    return {
        {RowNumberRole, "rowNumber"},
        {PacketIndexRole, "packetIndex"},
        {DirectionTextRole, "directionText"},
        {TimestampRole, "timestamp"},
        {CapturedLengthRole, "capturedLength"},
        {OriginalLengthRole, "originalLength"},
        {PayloadLengthRole, "payloadLength"},
        {IsIpFragmentedRole, "isIpFragmented"},
        {SuspectedTcpRetransmissionRole, "suspectedTcpRetransmission"},
        {TcpFlagsTextRole, "tcpFlagsText"},
    };
}

bool PacketListModel::hasVisibleMarkers() const noexcept {
    return has_visible_markers_;
}

int PacketListModel::rowForPacketIndex(const qulonglong packetIndex) const noexcept {
    for (std::size_t row = 0; row < items_.size(); ++row) {
        if (items_[row].packet_index == packetIndex) {
            return static_cast<int>(row);
        }
    }

    return -1;
}

void PacketListModel::refresh(const std::vector<PacketRow>& rows) {
    beginResetModel();
    items_.clear();
    items_.reserve(rows.size());

    for (const auto& row : rows) {
        items_.push_back(Item {
            .row_number = static_cast<qulonglong>(row.row_number),
            .packet_index = static_cast<qulonglong>(row.packet_index),
            .direction_text = QString::fromStdString(row.direction_text),
            .timestamp = QString::fromStdString(row.timestamp_text),
            .captured_length = row.captured_length,
            .original_length = row.original_length,
            .payload_length = row.payload_length,
            .is_ip_fragmented = row.is_ip_fragmented,
            .suspected_tcp_retransmission = row.suspected_tcp_retransmission,
            .tcp_flags_text = QString::fromStdString(row.tcp_flags_text),
        });
    }

    endResetModel();
    updateHasVisibleMarkers();
}

void PacketListModel::append(const std::vector<PacketRow>& rows) {
    if (rows.empty()) {
        return;
    }

    const auto beginIndex = static_cast<int>(items_.size());
    const auto endIndex = beginIndex + static_cast<int>(rows.size()) - 1;
    beginInsertRows(QModelIndex {}, beginIndex, endIndex);
    items_.reserve(items_.size() + rows.size());

    for (const auto& row : rows) {
        items_.push_back(Item {
            .row_number = static_cast<qulonglong>(row.row_number),
            .packet_index = static_cast<qulonglong>(row.packet_index),
            .direction_text = QString::fromStdString(row.direction_text),
            .timestamp = QString::fromStdString(row.timestamp_text),
            .captured_length = row.captured_length,
            .original_length = row.original_length,
            .payload_length = row.payload_length,
            .is_ip_fragmented = row.is_ip_fragmented,
            .suspected_tcp_retransmission = row.suspected_tcp_retransmission,
            .tcp_flags_text = QString::fromStdString(row.tcp_flags_text),
        });
    }

    endInsertRows();
    updateHasVisibleMarkers();
}

void PacketListModel::clear() {
    refresh({});
}

void PacketListModel::updateHasVisibleMarkers() {
    const bool nextHasVisibleMarkers = std::any_of(items_.begin(), items_.end(), [](const Item& item) {
        return item.suspected_tcp_retransmission;
    });

    if (has_visible_markers_ == nextHasVisibleMarkers) {
        return;
    }

    has_visible_markers_ = nextHasVisibleMarkers;
    emit hasVisibleMarkersChanged();
}

}  // namespace pfl
