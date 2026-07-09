#include "ui/app/ProtocolPathStatsModel.h"

#include <QString>

namespace pfl {

ProtocolPathStatsModel::ProtocolPathStatsModel(QObject* parent)
    : QAbstractListModel(parent) {
}

int ProtocolPathStatsModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid()) {
        return 0;
    }

    return static_cast<int>(rows_.size());
}

QVariant ProtocolPathStatsModel::data(const QModelIndex& index, const int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= rowCount()) {
        return {};
    }

    const auto& row = rows_[static_cast<std::size_t>(index.row())];
    switch (role) {
    case PathTextRole:
        return QString::fromStdString(row.path_text);
    case CompactTextRole:
        return QString::fromStdString(row.compact_text);
    case DepthRole:
        return static_cast<int>(row.depth);
    case FlowCountRole:
        return static_cast<qulonglong>(row.flow_count);
    case PacketCountRole:
        return static_cast<qulonglong>(row.packet_count);
    case TooltipRole:
        return QString::fromStdString(row.path_text);
    case IsTerminalRole:
        return !row.path.layers().empty();
    case RowIndexRole:
        return index.row();
    default:
        return {};
    }
}

QHash<int, QByteArray> ProtocolPathStatsModel::roleNames() const {
    return {
        {PathTextRole, "pathText"},
        {CompactTextRole, "compactText"},
        {DepthRole, "depth"},
        {FlowCountRole, "flowCount"},
        {PacketCountRole, "packetCount"},
        {TooltipRole, "tooltipText"},
        {IsTerminalRole, "isTerminal"},
        {RowIndexRole, "rowIndex"},
    };
}

void ProtocolPathStatsModel::refresh(const std::vector<ProtocolPathStatisticsRow>& rows) {
    beginResetModel();
    rows_ = rows;
    endResetModel();
}

void ProtocolPathStatsModel::clear() {
    if (rows_.empty()) {
        return;
    }

    beginResetModel();
    rows_.clear();
    endResetModel();
}

}  // namespace pfl
