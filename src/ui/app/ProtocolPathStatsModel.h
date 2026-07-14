#pragma once

#include <QAbstractListModel>
#include <QModelIndex>
#include <QString>
#include <QVariant>

#include <cstdint>
#include <set>
#include <unordered_map>
#include <vector>

#include "app/session/FlowRows.h"

namespace pfl {

class ProtocolPathStatsModel final : public QAbstractListModel {
    Q_OBJECT
    Q_PROPERTY(bool hasSelectedNode READ hasSelectedNode NOTIFY selectedNodeChanged)
    Q_PROPERTY(qulonglong selectedNodeId READ selectedNodeId NOTIFY selectedNodeChanged)
    Q_PROPERTY(QString selectedNodeFilterLabel READ selectedNodeFilterLabel NOTIFY selectedNodeChanged)
    Q_PROPERTY(qulonglong selectedNodeFlowCount READ selectedNodeFlowCount NOTIFY selectedNodeChanged)

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
        SelectedRole,
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
    Q_INVOKABLE void selectNode(qulonglong nodeId);
    Q_INVOKABLE void clearSelection();

    [[nodiscard]] bool hasSelectedNode() const noexcept;
    [[nodiscard]] qulonglong selectedNodeId() const noexcept;
    [[nodiscard]] QString selectedNodeFilterLabel() const;
    [[nodiscard]] qulonglong selectedNodeFlowCount() const noexcept;

signals:
    void selectedNodeChanged();

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
    std::uint64_t selected_node_id_ {kInvalidProtocolPathStatisticsNodeId};
    QString selected_node_filter_label_ {};
    qulonglong selected_node_flow_count_ {0U};
};

}  // namespace pfl
