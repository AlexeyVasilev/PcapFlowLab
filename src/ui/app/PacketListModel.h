#pragma once

#include <QAbstractListModel>
#include <QString>
#include <QVariant>

#include <vector>

#include "app/session/FlowRows.h"

namespace pfl {

class PacketListModel final : public QAbstractListModel {
    Q_OBJECT

public:
    enum Role {
        PacketIndexRole = Qt::UserRole + 1,
        TimestampRole,
        CapturedLengthRole,
        OriginalLengthRole,
        PayloadLengthRole,
        TcpFlagsTextRole,
    };

    explicit PacketListModel(QObject* parent = nullptr);

    [[nodiscard]] int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    [[nodiscard]] QHash<int, QByteArray> roleNames() const override;

    void refresh(const std::vector<PacketRow>& rows);
    void clear();

private:
    struct Item {
        qulonglong packet_index {0};
        QString timestamp {};
        uint captured_length {0};
        uint original_length {0};
        uint payload_length {0};
        QString tcp_flags_text {};
    };

    std::vector<Item> items_ {};
};

}  // namespace pfl
