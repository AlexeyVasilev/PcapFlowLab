#pragma once

#include <QAbstractListModel>
#include <QString>
#include <QVariant>

#include <functional>
#include <unordered_map>
#include <vector>

#include "app/session/ProtocolPathPresentation.h"
#include "app/session/FlowRows.h"

namespace pfl {

class FlowListModel final : public QAbstractListModel {
    Q_OBJECT

public:
    enum Role {
        FlowIndexRole = Qt::UserRole + 1,
        CheckedRole,
        FamilyRole,
        ProtocolRole,
        ProtocolHintRole,
        ServiceHintRole,
        ProtocolPathTextRole,
        ProtocolPathCompactTextRole,
        ProtocolPathBadgesRole,
        HasFragmentedPacketsRole,
        FragmentedPacketCountRole,
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
        protocol_hint,
        service_hint,
        fragmented_packets,
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
    Q_INVOKABLE void setFlowChecked(int flowIndex, bool checked);
    [[nodiscard]] Q_INVOKABLE bool isFlowChecked(int flowIndex) const noexcept;
    Q_INVOKABLE void clearCheckedFlows();
    [[nodiscard]] Q_INVOKABLE int checkedFlowCount() const noexcept;

    void refresh(const std::vector<FlowRow>& rows);
    void clear();
    void resetViewState();
    void setProtocolPathPresentationResolver(std::function<session_detail::ProtocolPathPresentation(ProtocolPathId)> resolver);
    void setFilterText(const QString& text);
    void setAllowedFlowIndices(std::vector<int> flowIndices);
    void clearAllowedFlowIndices();
    void setSortKey(SortKey key);
    void setSortAscending(bool ascending) noexcept;
    void setServiceHintForFlowIndex(int flowIndex, const QString& serviceHint);

    [[nodiscard]] const QString& filterText() const noexcept;
    [[nodiscard]] bool hasAllowedFlowIndexFilter() const noexcept;
    [[nodiscard]] SortKey sortKey() const noexcept;
    [[nodiscard]] bool sortAscending() const noexcept;
    [[nodiscard]] bool containsFlowIndex(int flowIndex) const noexcept;
    [[nodiscard]] int totalFlowCount() const noexcept;
    [[nodiscard]] std::vector<int> visibleFlowIndices() const;
    [[nodiscard]] std::vector<int> hiddenFlowIndices() const;
    [[nodiscard]] std::vector<int> checkedFlowIndices() const;
    [[nodiscard]] std::vector<int> uncheckedFlowIndices() const;

    struct Item {
        int flow_index {0};
        bool checked {false};
        QString family {};
        QString protocol {};
        QString protocol_hint {};
        QString service_hint {};
        ProtocolPathId protocol_path_id {kInvalidProtocolPathId};
        bool has_fragmented_packets {false};
        qulonglong fragmented_packets {0};
        QString address_a {};
        quint32 port_a {0};
        QString endpoint_a {};
        QString address_b {};
        quint32 port_b {0};
        QString endpoint_b {};
        qulonglong packets {0};
        qulonglong bytes {0};
    };

signals:
    void checkedFlowsChanged();

private:
    struct CachedProtocolPathPresentation {
        QString full_text {};
        QString compact_text {};
        QVariantList badges {};
    };

    [[nodiscard]] const CachedProtocolPathPresentation& protocolPathPresentation(ProtocolPathId protocolPathId) const;
    void rebuildVisibleItems();

    std::vector<Item> all_items_ {};
    std::vector<Item> visible_items_ {};
    std::function<session_detail::ProtocolPathPresentation(ProtocolPathId)> protocol_path_presentation_resolver_ {};
    mutable std::unordered_map<ProtocolPathId, CachedProtocolPathPresentation> protocol_path_presentation_cache_ {};
    QString filter_text_ {};
    std::vector<int> allowed_flow_indices_ {};
    bool has_allowed_flow_index_filter_ {false};
    SortKey sort_key_ {SortKey::index};
    bool sort_ascending_ {true};
};

}  // namespace pfl
