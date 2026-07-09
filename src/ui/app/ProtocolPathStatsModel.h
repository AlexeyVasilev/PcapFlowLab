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
        PathTextRole = Qt::UserRole + 1,
        CompactTextRole,
        DepthRole,
        FlowCountRole,
        PacketCountRole,
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
