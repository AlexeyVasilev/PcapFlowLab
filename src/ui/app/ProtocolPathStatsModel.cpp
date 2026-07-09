#include "ui/app/ProtocolPathStatsModel.h"

#include <QString>

namespace pfl {

namespace {

ProtocolPathStatisticsMode protocol_path_statistics_mode_from_int(const int mode) noexcept {
    if (mode == static_cast<int>(ProtocolPathStatisticsMode::identity_tree)) {
        return ProtocolPathStatisticsMode::identity_tree;
    }
    if (mode == static_cast<int>(ProtocolPathStatisticsMode::terminal_paths)) {
        return ProtocolPathStatisticsMode::terminal_paths;
    }
    return ProtocolPathStatisticsMode::kind_overview;
}

}  // namespace

ProtocolPathStatsModel::ProtocolPathStatsModel(QObject* parent)
    : QAbstractListModel(parent) {
}

int ProtocolPathStatsModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid()) {
        return 0;
    }

    return static_cast<int>(visible_row_indices_.size());
}

QVariant ProtocolPathStatsModel::data(const QModelIndex& index, const int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= rowCount()) {
        return {};
    }

    const auto row_index = visible_row_indices_[static_cast<std::size_t>(index.row())];
    const auto& row = rows_[row_index];
    switch (role) {
    case LayerTextRole:
        return QString::fromStdString(row.layer_text);
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
    case FlowPercentRole:
        return row.flow_percent;
    case PacketPercentRole:
        return row.packet_percent;
    case FlowCountTextRole:
        return QString::fromStdString(row.flow_count_text);
    case PacketCountTextRole:
        return QString::fromStdString(row.packet_count_text);
    case NodeIdRole:
        return static_cast<qulonglong>(row.node_id);
    case ParentNodeIdRole:
        return static_cast<qulonglong>(row.parent_node_id);
    case HasChildrenRole:
        return row.has_children;
    case ExpandedRole:
        return row.has_children && expanded_node_ids_.contains(row.node_id);
    case CanExpandRole:
        return isTreeMode() && row.has_children;
    case TooltipRole:
        return QString::fromStdString(row.path_text);
    case IsTerminalRole:
        return row.is_terminal;
    case RowIndexRole:
        return index.row();
    default:
        return {};
    }
}

QHash<int, QByteArray> ProtocolPathStatsModel::roleNames() const {
    return {
        {LayerTextRole, "layerText"},
        {PathTextRole, "pathText"},
        {CompactTextRole, "compactText"},
        {DepthRole, "depth"},
        {FlowCountRole, "flowCount"},
        {PacketCountRole, "packetCount"},
        {FlowPercentRole, "flowPercent"},
        {PacketPercentRole, "packetPercent"},
        {FlowCountTextRole, "flowCountText"},
        {PacketCountTextRole, "packetCountText"},
        {NodeIdRole, "nodeId"},
        {ParentNodeIdRole, "parentNodeId"},
        {HasChildrenRole, "hasChildren"},
        {ExpandedRole, "expanded"},
        {CanExpandRole, "canExpand"},
        {TooltipRole, "tooltipText"},
        {IsTerminalRole, "isTerminal"},
        {RowIndexRole, "rowIndex"},
    };
}

void ProtocolPathStatsModel::refresh(const CaptureProtocolPathSummary& summary) {
    beginResetModel();
    mode_ = summary.mode;
    rows_ = summary.rows;
    rebuildIndexMaps();
    expanded_node_ids_.clear();
    materializeVisibleRows();
    endResetModel();
}

void ProtocolPathStatsModel::clear() {
    if (rows_.empty() && visible_row_indices_.empty()) {
        return;
    }

    beginResetModel();
    rows_.clear();
    visible_row_indices_.clear();
    expanded_node_ids_.clear();
    row_index_by_node_id_.clear();
    mode_ = ProtocolPathStatisticsMode::kind_overview;
    endResetModel();
}

void ProtocolPathStatsModel::toggleExpanded(const qulonglong nodeId) {
    if (!isTreeMode()) {
        return;
    }

    const auto found = row_index_by_node_id_.find(static_cast<std::uint64_t>(nodeId));
    if (found == row_index_by_node_id_.end()) {
        return;
    }

    const auto& row = rows_[found->second];
    if (!row.has_children) {
        return;
    }

    if (expanded_node_ids_.contains(row.node_id)) {
        expanded_node_ids_.erase(row.node_id);
    } else {
        expanded_node_ids_.insert(row.node_id);
    }

    applyExpandedStateChange();
}

void ProtocolPathStatsModel::setExpanded(const qulonglong nodeId, const bool expanded) {
    if (!isTreeMode()) {
        return;
    }

    const auto found = row_index_by_node_id_.find(static_cast<std::uint64_t>(nodeId));
    if (found == row_index_by_node_id_.end()) {
        return;
    }

    const auto& row = rows_[found->second];
    if (!row.has_children) {
        return;
    }

    if (expanded) {
        expanded_node_ids_.insert(row.node_id);
    } else {
        expanded_node_ids_.erase(row.node_id);
    }

    applyExpandedStateChange();
}

void ProtocolPathStatsModel::expandAll() {
    if (!isTreeMode()) {
        return;
    }

    for (const auto& row : rows_) {
        if (row.has_children) {
            expanded_node_ids_.insert(row.node_id);
        }
    }

    applyExpandedStateChange();
}

void ProtocolPathStatsModel::collapseAll() {
    if (!isTreeMode()) {
        return;
    }

    expanded_node_ids_.clear();
    applyExpandedStateChange();
}

void ProtocolPathStatsModel::resetExpandedStateForMode(const int mode) {
    mode_ = protocol_path_statistics_mode_from_int(mode);
    expanded_node_ids_.clear();
    applyExpandedStateChange();
}

bool ProtocolPathStatsModel::canExpand() const noexcept {
    return isTreeMode();
}

bool ProtocolPathStatsModel::isTreeMode() const noexcept {
    return mode_ != ProtocolPathStatisticsMode::terminal_paths;
}

void ProtocolPathStatsModel::rebuildIndexMaps() {
    row_index_by_node_id_.clear();
    row_index_by_node_id_.reserve(rows_.size());
    for (std::size_t index = 0; index < rows_.size(); ++index) {
        row_index_by_node_id_.emplace(rows_[index].node_id, index);
    }
}

void ProtocolPathStatsModel::materializeVisibleRows() {
    visible_row_indices_.clear();
    visible_row_indices_.reserve(rows_.size());

    if (!isTreeMode()) {
        for (std::size_t index = 0; index < rows_.size(); ++index) {
            visible_row_indices_.push_back(index);
        }
        return;
    }

    std::unordered_map<std::uint64_t, bool> visible_by_node_id {};
    visible_by_node_id.reserve(rows_.size());

    for (std::size_t index = 0; index < rows_.size(); ++index) {
        const auto& row = rows_[index];
        const bool visible = row.parent_node_id == kInvalidProtocolPathStatisticsNodeId
            ? true
            : (visible_by_node_id.contains(row.parent_node_id) &&
                visible_by_node_id[row.parent_node_id] &&
                expanded_node_ids_.contains(row.parent_node_id));
        visible_by_node_id.emplace(row.node_id, visible);
        if (visible) {
            visible_row_indices_.push_back(index);
        }
    }
}

void ProtocolPathStatsModel::applyExpandedStateChange() {
    beginResetModel();
    materializeVisibleRows();
    endResetModel();
}

}  // namespace pfl
