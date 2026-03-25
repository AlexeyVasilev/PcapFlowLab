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
        AddressARole,
        PortARole,
        AddressBRole,
        PortBRole,
        PacketsRole,
        BytesRole,
    };

    enum class SortKey {
        index,
        family,
        protocol,
        address_a,
        port_a,
        address_b,
        port_b,
        packets,
        bytes,
    };

    explicit FlowListModel(QObject* parent = nullptr);

    [[nodiscard]] int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    [[nodiscard]] QHash<int, QByteArray> roleNames() const override;

    Q_INVOKABLE int rowForFlowIndex(int flowIndex) const noexcept;

    void refresh(const std::vector<FlowRow>& rows);
    void clear();
    void resetViewState();
    void setFilterText(const QString& text);
    void setSortKey(SortKey key);
    void setSortAscending(bool ascending) noexcept;

    [[nodiscard]] const QString& filterText() const noexcept;
    [[nodiscard]] SortKey sortKey() const noexcept;
    [[nodiscard]] bool sortAscending() const noexcept;
    [[nodiscard]] bool containsFlowIndex(int flowIndex) const noexcept;

    struct Item {
        int flow_index {0};
        QString family {};
        QString protocol {};
        QString address_a {};
        quint32 port_a {0};
        QString endpoint_a {};
        QString address_b {};
        quint32 port_b {0};
        QString endpoint_b {};
        qulonglong packets {0};
        qulonglong bytes {0};
    };

private:
    void rebuildVisibleItems();

    std::vector<Item> all_items_ {};
    std::vector<Item> visible_items_ {};
    QString filter_text_ {};
    SortKey sort_key_ {SortKey::index};
    bool sort_ascending_ {true};
};

}  // namespace pfl
