#pragma once

#include <QObject>
#include <QString>

namespace pfl {

class PacketDetailsViewModel final : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool hasPacket READ hasPacket NOTIFY changed)
    Q_PROPERTY(QString detailsTitle READ detailsTitle NOTIFY changed)
    Q_PROPERTY(QString summaryText READ summaryText NOTIFY changed)
    Q_PROPERTY(QString hexText READ hexText NOTIFY changed)
    Q_PROPERTY(QString payloadText READ payloadText NOTIFY changed)
    Q_PROPERTY(QString protocolText READ protocolText NOTIFY changed)

public:
    explicit PacketDetailsViewModel(QObject* parent = nullptr);

    [[nodiscard]] bool hasPacket() const noexcept;
    [[nodiscard]] const QString& detailsTitle() const noexcept;
    [[nodiscard]] const QString& summaryText() const noexcept;
    [[nodiscard]] const QString& hexText() const noexcept;
    [[nodiscard]] const QString& payloadText() const noexcept;
    [[nodiscard]] const QString& protocolText() const noexcept;

    void clear();
    void setDetailsTitle(const QString& text);
    void setPacketDetailsText(const QString& text);
    void setHexText(const QString& text);
    void setPayloadText(const QString& text);
    void setProtocolText(const QString& text);

signals:
    void changed();

private:
    void emitIfChanged(bool newHasPacket,
                       const QString& newDetailsTitle,
                       const QString& newSummaryText,
                       const QString& newHexText,
                       const QString& newPayloadText,
                       const QString& newProtocolText);

    bool has_packet_ {false};
    QString details_title_ {QStringLiteral("Packet Details")};
    QString summary_text_ {};
    QString hex_text_ {};
    QString payload_text_ {};
    QString protocol_text_ {};
};

}  // namespace pfl
