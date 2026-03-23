#pragma once

#include <QAbstractListModel>
#include <QString>
#include <QVariant>

#include <vector>

#include "app/session/FlowRows.h"

namespace pfl {

class FlowListModel final : public QAbstractListModel {
    Q_OBJECT

public:
    enum Role {
        FlowIndexRole = Qt::UserRole + 1,
        FamilyRole,
        ProtocolRole,
        EndpointARole,
        EndpointBRole,
        PacketsRole,
        BytesRole,
    };

    explicit FlowListModel(QObject* parent = nullptr);

    [[nodiscard]] int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    [[nodiscard]] QHash<int, QByteArray> roleNames() const override;

    void refresh(const std::vector<FlowRow>& rows);
    void clear();

private:
    struct Item {
        int flow_index {0};
        QString family {};
        QString protocol {};
        QString endpoint_a {};
        QString endpoint_b {};
        qulonglong packets {0};
        qulonglong bytes {0};
    };

    std::vector<Item> items_ {};
};

}  // namespace pfl
