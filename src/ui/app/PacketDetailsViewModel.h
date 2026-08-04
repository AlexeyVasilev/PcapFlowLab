#pragma once

#include <QObject>
#include <QString>
#include <QVariantList>

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
    Q_PROPERTY(QVariantList summaryLayers READ summaryLayers NOTIFY changed)
    Q_PROPERTY(QVariantList packetByteViewDescriptors READ packetByteViewDescriptors NOTIFY changed)
    Q_PROPERTY(QString selectedPacketByteViewId READ selectedPacketByteViewId NOTIFY changed)
    Q_PROPERTY(QString selectedPacketByteViewLabel READ selectedPacketByteViewLabel NOTIFY changed)
    Q_PROPERTY(bool selectedPacketByteViewAvailable READ selectedPacketByteViewAvailable NOTIFY changed)
    Q_PROPERTY(QString selectedPacketByteViewState READ selectedPacketByteViewState NOTIFY changed)
    Q_PROPERTY(qulonglong selectedPacketByteViewAvailableLength READ selectedPacketByteViewAvailableLength NOTIFY changed)
    Q_PROPERTY(QVariant selectedPacketByteViewDeclaredLength READ selectedPacketByteViewDeclaredLength NOTIFY changed)
    Q_PROPERTY(QString selectedPacketByteViewStatusText READ selectedPacketByteViewStatusText NOTIFY changed)
    Q_PROPERTY(QString selectedPacketByteViewText READ selectedPacketByteViewText NOTIFY changed)
    Q_PROPERTY(QString hexText READ hexText NOTIFY changed)
    Q_PROPERTY(QString payloadText READ payloadText NOTIFY changed)
    Q_PROPERTY(QString payloadTabTitle READ payloadTabTitle NOTIFY changed)
    Q_PROPERTY(bool streamItemDataAvailable READ streamItemDataAvailable NOTIFY changed)
    Q_PROPERTY(QString streamItemDataSemanticKind READ streamItemDataSemanticKind NOTIFY changed)
    Q_PROPERTY(QString streamItemDataSourceKind READ streamItemDataSourceKind NOTIFY changed)
    Q_PROPERTY(QString streamItemDataState READ streamItemDataState NOTIFY changed)
    Q_PROPERTY(QString streamItemDataAssemblyKind READ streamItemDataAssemblyKind NOTIFY changed)
    Q_PROPERTY(qulonglong streamItemDataAvailableLength READ streamItemDataAvailableLength NOTIFY changed)
    Q_PROPERTY(QVariant streamItemDataDeclaredLength READ streamItemDataDeclaredLength NOTIFY changed)
    Q_PROPERTY(QVariant streamItemDataContributingUnitCount READ streamItemDataContributingUnitCount NOTIFY changed)
    Q_PROPERTY(QString streamItemDataContributingUnitKind READ streamItemDataContributingUnitKind NOTIFY changed)
    Q_PROPERTY(QVariant streamItemDataLogicalOffset READ streamItemDataLogicalOffset NOTIFY changed)
    Q_PROPERTY(QString streamItemDataStatusText READ streamItemDataStatusText NOTIFY changed)
    Q_PROPERTY(QString streamItemDataText READ streamItemDataText NOTIFY changed)

public:
    explicit PacketDetailsViewModel(QObject* parent = nullptr);

    [[nodiscard]] bool hasPacket() const noexcept;
    [[nodiscard]] bool streamItemDetails() const noexcept;
    [[nodiscard]] const QString& detailsTitle() const noexcept;
    [[nodiscard]] const QString& headerPrimaryText() const noexcept;
    [[nodiscard]] const QString& headerSecondaryText() const noexcept;
    [[nodiscard]] const QString& badgeText() const noexcept;
    [[nodiscard]] const QString& summaryText() const noexcept;
    [[nodiscard]] const QVariantList& summaryLayers() const noexcept;
    [[nodiscard]] const QVariantList& packetByteViewDescriptors() const noexcept;
    [[nodiscard]] const QString& selectedPacketByteViewId() const noexcept;
    [[nodiscard]] const QString& selectedPacketByteViewLabel() const noexcept;
    [[nodiscard]] bool selectedPacketByteViewAvailable() const noexcept;
    [[nodiscard]] const QString& selectedPacketByteViewState() const noexcept;
    [[nodiscard]] qulonglong selectedPacketByteViewAvailableLength() const noexcept;
    [[nodiscard]] const QVariant& selectedPacketByteViewDeclaredLength() const noexcept;
    [[nodiscard]] const QString& selectedPacketByteViewStatusText() const noexcept;
    [[nodiscard]] const QString& selectedPacketByteViewText() const noexcept;
    [[nodiscard]] const QString& hexText() const noexcept;
    [[nodiscard]] const QString& payloadText() const noexcept;
    [[nodiscard]] const QString& payloadTabTitle() const noexcept;
    [[nodiscard]] bool streamItemDataAvailable() const noexcept;
    [[nodiscard]] const QString& streamItemDataSemanticKind() const noexcept;
    [[nodiscard]] const QString& streamItemDataSourceKind() const noexcept;
    [[nodiscard]] const QString& streamItemDataState() const noexcept;
    [[nodiscard]] const QString& streamItemDataAssemblyKind() const noexcept;
    [[nodiscard]] qulonglong streamItemDataAvailableLength() const noexcept;
    [[nodiscard]] const QVariant& streamItemDataDeclaredLength() const noexcept;
    [[nodiscard]] const QVariant& streamItemDataContributingUnitCount() const noexcept;
    [[nodiscard]] const QString& streamItemDataContributingUnitKind() const noexcept;
    [[nodiscard]] const QVariant& streamItemDataLogicalOffset() const noexcept;
    [[nodiscard]] const QString& streamItemDataStatusText() const noexcept;
    [[nodiscard]] const QString& streamItemDataText() const noexcept;

    void clear();
    void setDetailsTitle(const QString& text);
    void setStreamItemPresentation(const QString& primaryText, const QString& secondaryText, const QString& badgeText);
    void clearStreamItemPresentation();
    void setPacketDetailsText(const QString& text);
    void setSummaryLayers(const QVariantList& layers);
    void clearPacketBytePresentation();
    void setPacketBytePresentation(
        const QVariantList& descriptors,
        const QString& selectedId,
        const QString& selectedLabel,
        bool selectedAvailable,
        const QString& selectedState,
        qulonglong selectedAvailableLength,
        const QVariant& selectedDeclaredLength,
        const QString& statusText,
        const QString& formattedText
    );
    void setHexText(const QString& text);
    void setPayloadText(const QString& text);
    void setPayloadTabTitle(const QString& text);
    void clearStreamItemDataPresentation();
    void setStreamItemDataPresentation(
        bool available,
        const QString& semanticKind,
        const QString& sourceKind,
        const QString& state,
        const QString& assemblyKind,
        qulonglong availableLength,
        const QVariant& declaredLength,
        const QVariant& contributingUnitCount,
        const QString& contributingUnitKind,
        const QVariant& logicalOffset,
        const QString& statusText,
        const QString& formattedText
    );
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
                       const QVariantList& newSummaryLayers,
                       const QVariantList& newPacketByteViewDescriptors,
                       const QString& newSelectedPacketByteViewId,
                       const QString& newSelectedPacketByteViewLabel,
                       bool newSelectedPacketByteViewAvailable,
                       const QString& newSelectedPacketByteViewState,
                       qulonglong newSelectedPacketByteViewAvailableLength,
                       const QVariant& newSelectedPacketByteViewDeclaredLength,
                       const QString& newSelectedPacketByteViewStatusText,
                       const QString& newSelectedPacketByteViewText,
                       const QString& newHexText,
                       const QString& newPayloadText,
                       const QString& newPayloadTabTitle,
                       bool newStreamItemDataAvailable,
                       const QString& newStreamItemDataSemanticKind,
                       const QString& newStreamItemDataSourceKind,
                       const QString& newStreamItemDataState,
                       const QString& newStreamItemDataAssemblyKind,
                       qulonglong newStreamItemDataAvailableLength,
                       const QVariant& newStreamItemDataDeclaredLength,
                       const QVariant& newStreamItemDataContributingUnitCount,
                       const QString& newStreamItemDataContributingUnitKind,
                       const QVariant& newStreamItemDataLogicalOffset,
                       const QString& newStreamItemDataStatusText,
                       const QString& newStreamItemDataText);

    bool has_packet_ {false};
    bool stream_item_details_ {false};
    QString details_title_ {QStringLiteral("Packet Details")};
    QString header_primary_text_ {};
    QString header_secondary_text_ {};
    QString badge_text_ {};
    QString summary_text_ {};
    QVariantList summary_layers_ {};
    QVariantList packet_byte_view_descriptors_ {};
    QString selected_packet_byte_view_id_ {};
    QString selected_packet_byte_view_label_ {};
    bool selected_packet_byte_view_available_ {false};
    QString selected_packet_byte_view_state_ {};
    qulonglong selected_packet_byte_view_available_length_ {0U};
    QVariant selected_packet_byte_view_declared_length_ {};
    QString selected_packet_byte_view_status_text_ {};
    QString selected_packet_byte_view_text_ {};
    QString hex_text_ {};
    QString payload_text_ {};
    QString payload_tab_title_ {QStringLiteral("Payload")};
    bool stream_item_data_available_ {false};
    QString stream_item_data_semantic_kind_ {};
    QString stream_item_data_source_kind_ {};
    QString stream_item_data_state_ {};
    QString stream_item_data_assembly_kind_ {};
    qulonglong stream_item_data_available_length_ {0U};
    QVariant stream_item_data_declared_length_ {};
    QVariant stream_item_data_contributing_unit_count_ {};
    QString stream_item_data_contributing_unit_kind_ {};
    QVariant stream_item_data_logical_offset_ {};
    QString stream_item_data_status_text_ {};
    QString stream_item_data_text_ {};
};

}  // namespace pfl
