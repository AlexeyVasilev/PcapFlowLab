#pragma once

#include <QAbstractListModel>
#include <QModelIndex>
#include <QString>
#include <QVariant>

#include <vector>

#include "app/session/FlowRows.h"

namespace pfl {

class PacketListModel final : public QAbstractListModel {
    Q_OBJECT

public:
    enum Role {
        RowNumberRole = Qt::UserRole + 1,
        PacketIndexRole,
        DirectionTextRole,
        TimestampRole,
        CapturedLengthRole,
        OriginalLengthRole,
        PayloadLengthRole,
        IsIpFragmentedRole,
        SuspectedTcpRetransmissionRole,
        TcpFlagsTextRole,
    };

    explicit PacketListModel(QObject* parent = nullptr);

    [[nodiscard]] int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    [[nodiscard]] QHash<int, QByteArray> roleNames() const override;

    Q_INVOKABLE int rowForPacketIndex(qulonglong packetIndex) const noexcept;

    void refresh(const std::vector<PacketRow>& rows);
    void append(const std::vector<PacketRow>& rows);
    void clear();

private:
    struct Item {
        qulonglong row_number {0};
        qulonglong packet_index {0};
        QString direction_text {};
        QString timestamp {};
        uint captured_length {0};
        uint original_length {0};
        uint payload_length {0};
        bool is_ip_fragmented {false};
        bool suspected_tcp_retransmission {false};
        QString tcp_flags_text {};
    };

    std::vector<Item> items_ {};
};

}  // namespace pfl
