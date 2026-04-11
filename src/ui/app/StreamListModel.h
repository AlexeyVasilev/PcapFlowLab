#pragma once

#include <QAbstractListModel>
#include <QModelIndex>
#include <QString>
#include <QVariant>

#include <map>
#include <vector>

#include "app/session/FlowRows.h"

namespace pfl {

class StreamListModel final : public QAbstractListModel {
    Q_OBJECT

public:
    enum Role {
        StreamItemIndexRole = Qt::UserRole + 1,
        DirectionTextRole,
        LabelRole,
        ByteCountRole,
        PacketCountRole,
        SourcePacketsTextRole,
    };

    explicit StreamListModel(QObject* parent = nullptr);

    [[nodiscard]] int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    [[nodiscard]] QHash<int, QByteArray> roleNames() const override;

    void refresh(const std::vector<StreamItemRow>& rows, const std::map<std::uint64_t, std::uint64_t>& flowPacketNumbers = {});
    void append(const std::vector<StreamItemRow>& rows, const std::map<std::uint64_t, std::uint64_t>& flowPacketNumbers = {});
    void clear();

private:
    struct Item {
        qulonglong stream_item_index {0};
        QString direction_text {};
        QString label {};
        uint byte_count {0};
        uint packet_count {0};
        QString source_packets_text {};
    };

    std::vector<Item> items_ {};
};

}  // namespace pfl
