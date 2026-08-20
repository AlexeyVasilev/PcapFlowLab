#pragma once

#include <cstddef>
#include <vector>

#include <QObject>
#include <QString>
#include <QVariantList>

#include "app/session/AdvancedFlowFilter.h"
#include "app/session/AdvancedFlowFilterDocumentState.h"

namespace pfl {

class AdvancedFlowFilterEditorModel final : public QObject {
    Q_OBJECT
    Q_PROPERTY(int revision READ revision NOTIFY revisionChanged)
    Q_PROPERTY(QString validationText READ validationText NOTIFY validationTextChanged)
    Q_PROPERTY(bool draftClearAllAvailable READ draftClearAllAvailable NOTIFY draftClearAllAvailableChanged)

public:
    enum class AdvancedFlowFilterFiniteSection {
        address_family = 0,
        flow_protocol,
        detected_protocol,
        tls_version,
        quic_version,
        directionality,
        ports,
        ip_addresses,
        traffic,
        service,
    };

    enum class AdvancedFlowFilterTrafficMetric {
        packet_count = 0,
        original_bytes,
        captured_bytes,
        duration,
        max_original_packet_size,
        max_captured_packet_size,
        fragmented_packet_count,
        truncated_packet_count,
        tcp_syn_count,
        tcp_fin_count,
        tcp_rst_count,
    };

    enum class AdvancedFlowFilterTrafficUnit {
        bytes = 0,
        kib,
        mib,
        gib,
        tib,
        microseconds,
        milliseconds,
        seconds,
        minutes,
        hours,
    };

    explicit AdvancedFlowFilterEditorModel(
        session_detail::AdvancedFlowFilterDocumentState& document_state,
        QObject* parent = nullptr
    );

    [[nodiscard]] int revision() const noexcept;
    [[nodiscard]] QString validationText() const;

    [[nodiscard]] bool draftClearAllAvailable() const noexcept;
    Q_INVOKABLE bool sectionEnabled(int section) const noexcept;
    Q_INVOKABLE bool sectionHasExclusions(int section) const noexcept;
    Q_INVOKABLE QVariantList includeOptions(int section) const;
    Q_INVOKABLE QVariantList excludeOptions(int section) const;
    Q_INVOKABLE QVariantList portScopeOptions() const;
    Q_INVOKABLE QVariantList addressScopeOptions() const;
    Q_INVOKABLE QVariantList portRows(bool exclude) const;
    Q_INVOKABLE QVariantList addressRows(bool exclude) const;
    Q_INVOKABLE QVariantList commonTrafficRows() const;
    Q_INVOKABLE QVariantList additionalTrafficRows() const;
    Q_INVOKABLE bool trafficAdditionalFiltersExpandedSuggested() const noexcept;
    Q_INVOKABLE void setTrafficMinText(int metric, const QString& text);
    Q_INVOKABLE void setTrafficMaxText(int metric, const QString& text);
    Q_INVOKABLE bool setTrafficUnit(int metric, int unit);
    Q_INVOKABLE bool serviceStateChecked(bool exclude, int stateKind) const noexcept;
    Q_INVOKABLE QVariantList serviceOperatorOptions() const;
    Q_INVOKABLE QVariantList serviceTextRows(bool exclude) const;
    Q_INVOKABLE void setServiceStateChecked(bool exclude, int stateKind, bool checked);
    Q_INVOKABLE void addServiceTextRow(bool exclude);
    Q_INVOKABLE void removeServiceTextRow(bool exclude, int row);
    Q_INVOKABLE void setServiceTextRowKind(bool exclude, int row, int kind);
    Q_INVOKABLE void setServiceTextRowCaseSensitive(bool exclude, int row, bool caseSensitive);
    Q_INVOKABLE void setServiceTextRowText(bool exclude, int row, const QString& text);
    Q_INVOKABLE void setSectionEnabled(int section, bool enabled);
    Q_INVOKABLE void setOptionChecked(int section, int value, bool exclude, bool checked);
    Q_INVOKABLE void addPortRow(bool exclude);
    Q_INVOKABLE void removePortRow(bool exclude, int row);
    Q_INVOKABLE void setPortRowScope(bool exclude, int row, int scope);
    Q_INVOKABLE void setPortRowRangeEnabled(bool exclude, int row, bool enabled);
    Q_INVOKABLE void setPortRowPrimaryText(bool exclude, int row, const QString& text);
    Q_INVOKABLE void setPortRowSecondaryText(bool exclude, int row, const QString& text);
    Q_INVOKABLE void addAddressRow(bool exclude);
    Q_INVOKABLE void removeAddressRow(bool exclude, int row);
    Q_INVOKABLE void setAddressRowScope(bool exclude, int row, int scope);
    Q_INVOKABLE void setAddressRowSubnetEnabled(bool exclude, int row, bool enabled);
    Q_INVOKABLE void setAddressRowAddressText(bool exclude, int row, const QString& text);
    Q_INVOKABLE void setAddressRowPrefixText(bool exclude, int row, const QString& text);

    void initializeFromCurrentDocument();
    void clearTransientState() noexcept;
    [[nodiscard]] bool synchronizeDraftSections(QString* errorText = nullptr);
    void setValidationText(const QString& text);

signals:
    void revisionChanged();
    void validationTextChanged();
    void draftClearAllAvailableChanged();
    void stateChanged();

private:
    struct AdvancedFlowFilterPortEditorRow {
        session_detail::AdvancedFlowFilterPortScope scope {session_detail::AdvancedFlowFilterPortScope::either_endpoint};
        bool range_enabled {false};
        QString primary_text {};
        QString secondary_text {};
    };

    struct AdvancedFlowFilterAddressEditorRow {
        session_detail::AdvancedFlowFilterEndpointScope scope {session_detail::AdvancedFlowFilterEndpointScope::either_endpoint};
        bool subnet_enabled {false};
        QString address_text {};
        QString prefix_text {};
    };

    struct AdvancedFlowFilterTrafficEditorRow {
        QString min_text {};
        QString max_text {};
        AdvancedFlowFilterTrafficUnit unit {AdvancedFlowFilterTrafficUnit::bytes};
    };

    struct AdvancedFlowFilterServiceTextEditorRow {
        session_detail::AdvancedFlowFilterServicePredicateKind kind {
            session_detail::AdvancedFlowFilterServicePredicateKind::contains
        };
        bool case_sensitive {false};
        QString text {};
    };

    void ensureEditingInitialized();
    void clearValidationText();
    void notifyRowsChanged();
    void notifyTextFieldEdited();
    void notifyStateChanged();
    [[nodiscard]] QVariantList buildPortRowList(bool exclude) const;
    [[nodiscard]] QVariantList buildAddressRowList(bool exclude) const;
    [[nodiscard]] QVariantList buildTrafficRowList(bool additional) const;
    [[nodiscard]] QVariantList buildServiceTextRowList(bool exclude) const;

    session_detail::AdvancedFlowFilterDocumentState& document_state_;
    int revision_ {0};
    bool editing_initialized_ {false};
    std::vector<AdvancedFlowFilterPortEditorRow> port_include_rows_ {};
    std::vector<AdvancedFlowFilterPortEditorRow> port_exclude_rows_ {};
    std::vector<AdvancedFlowFilterAddressEditorRow> address_include_rows_ {};
    std::vector<AdvancedFlowFilterAddressEditorRow> address_exclude_rows_ {};
    std::vector<AdvancedFlowFilterTrafficEditorRow> traffic_rows_ {};
    bool service_include_known_ {false};
    bool service_include_unknown_ {false};
    bool service_exclude_known_ {false};
    bool service_exclude_unknown_ {false};
    std::vector<AdvancedFlowFilterServiceTextEditorRow> service_include_text_rows_ {};
    std::vector<AdvancedFlowFilterServiceTextEditorRow> service_exclude_text_rows_ {};
    QString validation_text_ {};
};

}  // namespace pfl
