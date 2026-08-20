#pragma once

#include <optional>
#include <vector>

#include <QObject>
#include <QString>

#include "app/session/AdvancedFlowFilter.h"
#include "app/session/CaptureSession.h"
#include "ui/app/ProtocolPathStatsModel.h"

namespace pfl {

class AdvancedFlowFilterProtocolPathSelectorModel final : public QObject {
    Q_OBJECT
    Q_PROPERTY(int revision READ revision NOTIFY stateChanged)
    Q_PROPERTY(int mode READ mode WRITE setMode NOTIFY stateChanged)
    Q_PROPERTY(QObject* statsModel READ statsModel CONSTANT)
    Q_PROPERTY(bool hasCapture READ hasCapture NOTIFY stateChanged)
    Q_PROPERTY(bool selectionAvailable READ selectionAvailable NOTIFY stateChanged)
    Q_PROPERTY(QString statusText READ statusText NOTIFY stateChanged)

public:
    explicit AdvancedFlowFilterProtocolPathSelectorModel(QObject* parent = nullptr);

    [[nodiscard]] int revision() const noexcept;
    [[nodiscard]] int mode() const noexcept;
    [[nodiscard]] QObject* statsModel() noexcept;
    [[nodiscard]] bool hasCapture() const noexcept;
    [[nodiscard]] bool selectionAvailable() const noexcept;
    [[nodiscard]] QString statusText() const;

    void setCaptureSession(const CaptureSession* session);
    void selectPredicate(const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate);
    [[nodiscard]] std::optional<session_detail::AdvancedFlowFilterProtocolPathPredicate> selectedPredicate() const;

    Q_INVOKABLE void setMode(int mode);
    Q_INVOKABLE void selectNode(qulonglong nodeId);
    Q_INVOKABLE void clearSelection();

signals:
    void stateChanged();

private:
    void refreshSummary(bool preserveSelection);
    void emitStateChanged();
    [[nodiscard]] const ProtocolPathStatisticsRow* selectedRow() const noexcept;

    const CaptureSession* session_ {nullptr};
    ProtocolPathStatsModel stats_model_ {};
    CaptureProtocolPathSummary summary_ {};
    ProtocolPathStatisticsMode mode_ {ProtocolPathStatisticsMode::kind_overview};
    QString status_text_ {};
    int revision_ {0};
};

}  // namespace pfl
