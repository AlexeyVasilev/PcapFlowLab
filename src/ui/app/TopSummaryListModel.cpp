#include "ui/app/TopSummaryListModel.h"

namespace pfl {

TopSummaryListModel::TopSummaryListModel(QObject* parent)
    : QAbstractListModel(parent) {
}

int TopSummaryListModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid()) {
        return 0;
    }

    return static_cast<int>(items_.size());
}

QVariant TopSummaryListModel::data(const QModelIndex& index, const int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= rowCount()) {
        return {};
    }

    const Item& item = items_[static_cast<std::size_t>(index.row())];
    switch (role) {
    case ItemRole:
        return item.label;
    case PacketsRole:
        return item.packets;
    case BytesRole:
        return item.bytes;
    default:
        return {};
    }
}

QHash<int, QByteArray> TopSummaryListModel::roleNames() const {
    return {
        {ItemRole, "itemLabel"},
        {PacketsRole, "packets"},
        {BytesRole, "bytes"},
    };
}

void TopSummaryListModel::refreshEndpoints(const std::vector<TopEndpointRow>& rows) {
    std::vector<Item> items {};
    items.reserve(rows.size());

    for (const auto& row : rows) {
        items.push_back(Item {
            .label = QString::fromStdString(row.endpoint),
            .packets = static_cast<qulonglong>(row.packet_count),
            .bytes = static_cast<qulonglong>(row.total_bytes),
        });
    }

    setItems(std::move(items));
}

void TopSummaryListModel::refreshPorts(const std::vector<TopPortRow>& rows) {
    std::vector<Item> items {};
    items.reserve(rows.size());

    for (const auto& row : rows) {
        items.push_back(Item {
            .label = QString::number(row.port),
            .packets = static_cast<qulonglong>(row.packet_count),
            .bytes = static_cast<qulonglong>(row.total_bytes),
        });
    }

    setItems(std::move(items));
}

void TopSummaryListModel::clear() {
    setItems({});
}

void TopSummaryListModel::setItems(std::vector<Item> items) {
    beginResetModel();
    items_ = std::move(items);
    endResetModel();
}

}  // namespace pfl
