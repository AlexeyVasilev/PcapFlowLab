#include "ui/app/StreamListModel.h"

namespace pfl {

StreamListModel::StreamListModel(QObject* parent)
    : QAbstractListModel(parent) {
}

int StreamListModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid()) {
        return 0;
    }

    return static_cast<int>(items_.size());
}

QVariant StreamListModel::data(const QModelIndex& index, const int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= rowCount()) {
        return {};
    }

    const Item& item = items_[static_cast<std::size_t>(index.row())];
    switch (role) {
    case StreamItemIndexRole:
        return QVariant::fromValue(item.stream_item_index);
    case DirectionTextRole:
        return item.direction_text;
    case LabelRole:
        return item.label;
    case ByteCountRole:
        return item.byte_count;
    case PacketCountRole:
        return item.packet_count;
    default:
        return {};
    }
}

QHash<int, QByteArray> StreamListModel::roleNames() const {
    return {
        {StreamItemIndexRole, "streamItemIndex"},
        {DirectionTextRole, "directionText"},
        {LabelRole, "label"},
        {ByteCountRole, "byteCount"},
        {PacketCountRole, "packetCount"},
    };
}

void StreamListModel::refresh(const std::vector<StreamItemRow>& rows) {
    beginResetModel();
    items_.clear();
    items_.reserve(rows.size());

    for (const auto& row : rows) {
        items_.push_back(Item {
            .stream_item_index = static_cast<qulonglong>(row.stream_item_index),
            .direction_text = QString::fromStdString(row.direction_text),
            .label = QString::fromStdString(row.label),
            .byte_count = row.byte_count,
            .packet_count = row.packet_count,
        });
    }

    endResetModel();
}

void StreamListModel::append(const std::vector<StreamItemRow>& rows) {
    if (rows.empty()) {
        return;
    }

    const auto beginIndex = static_cast<int>(items_.size());
    const auto endIndex = beginIndex + static_cast<int>(rows.size()) - 1;
    beginInsertRows(QModelIndex {}, beginIndex, endIndex);
    items_.reserve(items_.size() + rows.size());

    for (const auto& row : rows) {
        items_.push_back(Item {
            .stream_item_index = static_cast<qulonglong>(row.stream_item_index),
            .direction_text = QString::fromStdString(row.direction_text),
            .label = QString::fromStdString(row.label),
            .byte_count = row.byte_count,
            .packet_count = row.packet_count,
        });
    }

    endInsertRows();
}

void StreamListModel::clear() {
    refresh({});
}

}  // namespace pfl
