#pragma once

#include <QObject>
#include <QString>

namespace pfl {

class PacketDetailsViewModel final : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool hasPacket READ hasPacket NOTIFY changed)
    Q_PROPERTY(QString summaryText READ summaryText NOTIFY changed)
    Q_PROPERTY(QString hexText READ hexText NOTIFY changed)

public:
    explicit PacketDetailsViewModel(QObject* parent = nullptr);

    [[nodiscard]] bool hasPacket() const noexcept;
    [[nodiscard]] const QString& summaryText() const noexcept;
    [[nodiscard]] const QString& hexText() const noexcept;

    void clear();
    void setPacketDetailsText(const QString& text);
    void setHexText(const QString& text);

signals:
    void changed();

private:
    void emitIfChanged(bool newHasPacket, const QString& newSummaryText, const QString& newHexText);

    bool has_packet_ {false};
    QString summary_text_ {};
    QString hex_text_ {};
};

}  // namespace pfl
