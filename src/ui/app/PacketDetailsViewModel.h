#pragma once

#include <QObject>
#include <QString>

namespace pfl {

class PacketDetailsViewModel final : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool hasPacket READ hasPacket NOTIFY changed)
    Q_PROPERTY(bool streamItemDetails READ streamItemDetails NOTIFY changed)
    Q_PROPERTY(QString detailsTitle READ detailsTitle NOTIFY changed)
    Q_PROPERTY(QString headerPrimaryText READ headerPrimaryText NOTIFY changed)
    Q_PROPERTY(QString headerSecondaryText READ headerSecondaryText NOTIFY changed)
    Q_PROPERTY(QString badgeText READ badgeText NOTIFY changed)
    Q_PROPERTY(QString summaryText READ summaryText NOTIFY changed)
    Q_PROPERTY(QString hexText READ hexText NOTIFY changed)
    Q_PROPERTY(QString payloadText READ payloadText NOTIFY changed)
    Q_PROPERTY(QString payloadTabTitle READ payloadTabTitle NOTIFY changed)
    Q_PROPERTY(QString protocolText READ protocolText NOTIFY changed)

public:
    explicit PacketDetailsViewModel(QObject* parent = nullptr);

    [[nodiscard]] bool hasPacket() const noexcept;
    [[nodiscard]] bool streamItemDetails() const noexcept;
    [[nodiscard]] const QString& detailsTitle() const noexcept;
    [[nodiscard]] const QString& headerPrimaryText() const noexcept;
    [[nodiscard]] const QString& headerSecondaryText() const noexcept;
    [[nodiscard]] const QString& badgeText() const noexcept;
    [[nodiscard]] const QString& summaryText() const noexcept;
    [[nodiscard]] const QString& hexText() const noexcept;
    [[nodiscard]] const QString& payloadText() const noexcept;
    [[nodiscard]] const QString& payloadTabTitle() const noexcept;
    [[nodiscard]] const QString& protocolText() const noexcept;

    void clear();
    void setDetailsTitle(const QString& text);
    void setStreamItemPresentation(const QString& primaryText, const QString& secondaryText, const QString& badgeText);
    void clearStreamItemPresentation();
    void setPacketDetailsText(const QString& text);
    void setHexText(const QString& text);
    void setPayloadText(const QString& text);
    void setPayloadTabTitle(const QString& text);
    void setProtocolText(const QString& text);

signals:
    void changed();

private:
    void emitIfChanged(bool newHasPacket,
                       bool newStreamItemDetails,
                       const QString& newDetailsTitle,
                       const QString& newHeaderPrimaryText,
                       const QString& newHeaderSecondaryText,
                       const QString& newBadgeText,
                       const QString& newSummaryText,
                       const QString& newHexText,
                       const QString& newPayloadText,
                       const QString& newPayloadTabTitle,
                       const QString& newProtocolText);

    bool has_packet_ {false};
    bool stream_item_details_ {false};
    QString details_title_ {QStringLiteral("Packet Details")};
    QString header_primary_text_ {};
    QString header_secondary_text_ {};
    QString badge_text_ {};
    QString summary_text_ {};
    QString hex_text_ {};
    QString payload_text_ {};
    QString payload_tab_title_ {QStringLiteral("Payload")};
    QString protocol_text_ {};
};

}  // namespace pfl
