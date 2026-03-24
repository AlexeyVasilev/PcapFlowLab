#pragma once

#include <QAbstractListModel>
#include <QString>
#include <QVariant>

#include <vector>

#include "app/session/FlowRows.h"

namespace pfl {

class TopSummaryListModel final : public QAbstractListModel {
    Q_OBJECT

public:
    enum Role {
        ItemRole = Qt::UserRole + 1,
        PacketsRole,
        BytesRole,
    };

    explicit TopSummaryListModel(QObject* parent = nullptr);

    [[nodiscard]] int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    [[nodiscard]] QHash<int, QByteArray> roleNames() const override;

    void refreshEndpoints(const std::vector<TopEndpointRow>& rows);
    void refreshPorts(const std::vector<TopPortRow>& rows);
    void clear();

private:
    struct Item {
        QString label {};
        qulonglong packets {0};
        qulonglong bytes {0};
    };

    void setItems(std::vector<Item> items);

    std::vector<Item> items_ {};
};

}  // namespace pfl
