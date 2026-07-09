#pragma once

#include <QAbstractListModel>
#include <QModelIndex>
#include <QVariant>

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
        TooltipRole,
        IsTerminalRole,
        RowIndexRole,
    };

    explicit ProtocolPathStatsModel(QObject* parent = nullptr);

    [[nodiscard]] int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    [[nodiscard]] QHash<int, QByteArray> roleNames() const override;

    void refresh(const std::vector<ProtocolPathStatisticsRow>& rows);
    void clear();

private:
    std::vector<ProtocolPathStatisticsRow> rows_ {};
};

}  // namespace pfl
