#pragma once

#include <QAbstractListModel>
#include <QModelIndex>
#include <QVariant>

#include <cstdint>
#include <set>
#include <unordered_map>
#include <vector>

#include "app/session/FlowRows.h"

namespace pfl {

class ProtocolPathStatsModel final : public QAbstractListModel {
    Q_OBJECT

public:
    enum Role {
        LayerTextRole = Qt::UserRole + 1,
        PathTextRole,
        CompactTextRole,
        DepthRole,
        FlowCountRole,
        PacketCountRole,
        FlowPercentRole,
        PacketPercentRole,
        FlowCountTextRole,
        PacketCountTextRole,
        OriginalByteCountRole,
        OriginalBytePercentRole,
        OriginalByteCountTextRole,
        NodeIdRole,
        ParentNodeIdRole,
        HasChildrenRole,
        ExpandedRole,
        CanExpandRole,
        TooltipRole,
        IsTerminalRole,
        RowIndexRole,
    };

    explicit ProtocolPathStatsModel(QObject* parent = nullptr);

    [[nodiscard]] int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    [[nodiscard]] QHash<int, QByteArray> roleNames() const override;

    void refresh(const CaptureProtocolPathSummary& summary);
    void clear();

    Q_INVOKABLE void toggleExpanded(qulonglong nodeId);
    Q_INVOKABLE void setExpanded(qulonglong nodeId, bool expanded);
    Q_INVOKABLE void expandAll();
    Q_INVOKABLE void collapseAll();
    Q_INVOKABLE void resetExpandedStateForMode(int mode);
    [[nodiscard]] Q_INVOKABLE bool canExpand() const noexcept;

private:
    [[nodiscard]] bool isTreeMode() const noexcept;
    void rebuildIndexMaps();
    void materializeVisibleRows();
    void applyExpandedStateChange();

    ProtocolPathStatisticsMode mode_ {ProtocolPathStatisticsMode::kind_overview};
    std::vector<ProtocolPathStatisticsRow> rows_ {};
    std::vector<std::size_t> visible_row_indices_ {};
    std::set<std::uint64_t> expanded_node_ids_ {};
    std::unordered_map<std::uint64_t, std::size_t> row_index_by_node_id_ {};
};

}  // namespace pfl
