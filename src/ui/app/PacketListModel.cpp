#include "ui/app/PacketListModel.h"

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
    case TcpFlagsTextRole:
        return item.tcp_flags_text;
    default:
        return {};
    }
}

QHash<int, QByteArray> PacketListModel::roleNames() const {
    return {
        {PacketIndexRole, "packetIndex"},
        {DirectionTextRole, "directionText"},
        {TimestampRole, "timestamp"},
        {CapturedLengthRole, "capturedLength"},
        {OriginalLengthRole, "originalLength"},
        {PayloadLengthRole, "payloadLength"},
        {TcpFlagsTextRole, "tcpFlagsText"},
    };
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
            .packet_index = static_cast<qulonglong>(row.packet_index),
            .direction_text = QString::fromStdString(row.direction_text),
            .timestamp = QString::fromStdString(row.timestamp_text),
            .captured_length = row.captured_length,
            .original_length = row.original_length,
            .payload_length = row.payload_length,
            .tcp_flags_text = QString::fromStdString(row.tcp_flags_text),
        });
    }

    endResetModel();
}

void PacketListModel::clear() {
    refresh({});
}

}  // namespace pfl
