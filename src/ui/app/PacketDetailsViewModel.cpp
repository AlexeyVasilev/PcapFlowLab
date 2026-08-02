#include "ui/app/PacketDetailsViewModel.h"

namespace pfl {

PacketDetailsViewModel::PacketDetailsViewModel(QObject* parent)
    : QObject(parent) {
}

bool PacketDetailsViewModel::hasPacket() const noexcept {
    return has_packet_;
}

bool PacketDetailsViewModel::streamItemDetails() const noexcept {
    return stream_item_details_;
}

const QString& PacketDetailsViewModel::detailsTitle() const noexcept {
    return details_title_;
}

const QString& PacketDetailsViewModel::headerPrimaryText() const noexcept {
    return header_primary_text_;
}

const QString& PacketDetailsViewModel::headerSecondaryText() const noexcept {
    return header_secondary_text_;
}

const QString& PacketDetailsViewModel::badgeText() const noexcept {
    return badge_text_;
}

const QString& PacketDetailsViewModel::summaryText() const noexcept {
    return summary_text_;
}

const QVariantList& PacketDetailsViewModel::summaryLayers() const noexcept {
    return summary_layers_;
}

const QVariantList& PacketDetailsViewModel::packetByteViewDescriptors() const noexcept {
    return packet_byte_view_descriptors_;
}

const QString& PacketDetailsViewModel::selectedPacketByteViewId() const noexcept {
    return selected_packet_byte_view_id_;
}

const QString& PacketDetailsViewModel::selectedPacketByteViewLabel() const noexcept {
    return selected_packet_byte_view_label_;
}

const QString& PacketDetailsViewModel::selectedPacketByteViewState() const noexcept {
    return selected_packet_byte_view_state_;
}

qulonglong PacketDetailsViewModel::selectedPacketByteViewAvailableLength() const noexcept {
    return selected_packet_byte_view_available_length_;
}

const QVariant& PacketDetailsViewModel::selectedPacketByteViewDeclaredLength() const noexcept {
    return selected_packet_byte_view_declared_length_;
}

const QString& PacketDetailsViewModel::selectedPacketByteViewStatusText() const noexcept {
    return selected_packet_byte_view_status_text_;
}

const QString& PacketDetailsViewModel::selectedPacketByteViewText() const noexcept {
    return selected_packet_byte_view_text_;
}

const QString& PacketDetailsViewModel::hexText() const noexcept {
    return hex_text_;
}

const QString& PacketDetailsViewModel::payloadText() const noexcept {
    return payload_text_;
}

const QString& PacketDetailsViewModel::payloadTabTitle() const noexcept {
    return payload_tab_title_;
}

const QString& PacketDetailsViewModel::protocolText() const noexcept {
    return protocol_text_;
}

void PacketDetailsViewModel::clear() {
    emitIfChanged(
        false,
        false,
        QStringLiteral("Packet Details"),
        {},
        {},
        {},
        {},
        {},
        {},
        {},
        {},
        {},
        0U,
        {},
        {},
        {},
        {},
        {},
        QStringLiteral("Payload"),
        {}
    );
}

void PacketDetailsViewModel::setDetailsTitle(const QString& text) {
    emitIfChanged(has_packet_, stream_item_details_, text, header_primary_text_, header_secondary_text_, badge_text_, summary_text_, summary_layers_, packet_byte_view_descriptors_, selected_packet_byte_view_id_, selected_packet_byte_view_label_, selected_packet_byte_view_state_, selected_packet_byte_view_available_length_, selected_packet_byte_view_declared_length_, selected_packet_byte_view_status_text_, selected_packet_byte_view_text_, hex_text_, payload_text_, payload_tab_title_, protocol_text_);
}

void PacketDetailsViewModel::setStreamItemPresentation(const QString& primaryText, const QString& secondaryText, const QString& badgeText) {
    emitIfChanged(has_packet_, true, details_title_, primaryText, secondaryText, badgeText, summary_text_, summary_layers_, packet_byte_view_descriptors_, selected_packet_byte_view_id_, selected_packet_byte_view_label_, selected_packet_byte_view_state_, selected_packet_byte_view_available_length_, selected_packet_byte_view_declared_length_, selected_packet_byte_view_status_text_, selected_packet_byte_view_text_, hex_text_, payload_text_, payload_tab_title_, protocol_text_);
}

void PacketDetailsViewModel::clearStreamItemPresentation() {
    emitIfChanged(has_packet_, false, details_title_, {}, {}, {}, summary_text_, summary_layers_, packet_byte_view_descriptors_, selected_packet_byte_view_id_, selected_packet_byte_view_label_, selected_packet_byte_view_state_, selected_packet_byte_view_available_length_, selected_packet_byte_view_declared_length_, selected_packet_byte_view_status_text_, selected_packet_byte_view_text_, hex_text_, payload_text_, payload_tab_title_, protocol_text_);
}

void PacketDetailsViewModel::setPacketDetailsText(const QString& text) {
    emitIfChanged(!text.isEmpty() || !summary_layers_.isEmpty() || !packet_byte_view_descriptors_.isEmpty() || !selected_packet_byte_view_text_.isEmpty() || !hex_text_.isEmpty() || !payload_text_.isEmpty() || !protocol_text_.isEmpty(), stream_item_details_, details_title_, header_primary_text_, header_secondary_text_, badge_text_, text, summary_layers_, packet_byte_view_descriptors_, selected_packet_byte_view_id_, selected_packet_byte_view_label_, selected_packet_byte_view_state_, selected_packet_byte_view_available_length_, selected_packet_byte_view_declared_length_, selected_packet_byte_view_status_text_, selected_packet_byte_view_text_, hex_text_, payload_text_, payload_tab_title_, protocol_text_);
}

void PacketDetailsViewModel::setSummaryLayers(const QVariantList& layers) {
    emitIfChanged(!summary_text_.isEmpty() || !layers.isEmpty() || !packet_byte_view_descriptors_.isEmpty() || !selected_packet_byte_view_text_.isEmpty() || !hex_text_.isEmpty() || !payload_text_.isEmpty() || !protocol_text_.isEmpty(), stream_item_details_, details_title_, header_primary_text_, header_secondary_text_, badge_text_, summary_text_, layers, packet_byte_view_descriptors_, selected_packet_byte_view_id_, selected_packet_byte_view_label_, selected_packet_byte_view_state_, selected_packet_byte_view_available_length_, selected_packet_byte_view_declared_length_, selected_packet_byte_view_status_text_, selected_packet_byte_view_text_, hex_text_, payload_text_, payload_tab_title_, protocol_text_);
}

void PacketDetailsViewModel::clearPacketBytePresentation() {
    emitIfChanged(!summary_text_.isEmpty() || !summary_layers_.isEmpty() || !hex_text_.isEmpty() || !payload_text_.isEmpty() || !protocol_text_.isEmpty(), stream_item_details_, details_title_, header_primary_text_, header_secondary_text_, badge_text_, summary_text_, summary_layers_, {}, {}, {}, {}, 0U, {}, {}, {}, hex_text_, payload_text_, payload_tab_title_, protocol_text_);
}

void PacketDetailsViewModel::setPacketBytePresentation(
    const QVariantList& descriptors,
    const QString& selectedId,
    const QString& selectedLabel,
    const QString& selectedState,
    const qulonglong selectedAvailableLength,
    const QVariant& selectedDeclaredLength,
    const QString& statusText,
    const QString& formattedText
) {
    emitIfChanged(!summary_text_.isEmpty() || !summary_layers_.isEmpty() || !descriptors.isEmpty() || !formattedText.isEmpty() || !hex_text_.isEmpty() || !payload_text_.isEmpty() || !protocol_text_.isEmpty(), stream_item_details_, details_title_, header_primary_text_, header_secondary_text_, badge_text_, summary_text_, summary_layers_, descriptors, selectedId, selectedLabel, selectedState, selectedAvailableLength, selectedDeclaredLength, statusText, formattedText, hex_text_, payload_text_, payload_tab_title_, protocol_text_);
}

void PacketDetailsViewModel::setHexText(const QString& text) {
    emitIfChanged(!summary_text_.isEmpty() || !summary_layers_.isEmpty() || !packet_byte_view_descriptors_.isEmpty() || !selected_packet_byte_view_text_.isEmpty() || !text.isEmpty() || !payload_text_.isEmpty() || !protocol_text_.isEmpty(), stream_item_details_, details_title_, header_primary_text_, header_secondary_text_, badge_text_, summary_text_, summary_layers_, packet_byte_view_descriptors_, selected_packet_byte_view_id_, selected_packet_byte_view_label_, selected_packet_byte_view_state_, selected_packet_byte_view_available_length_, selected_packet_byte_view_declared_length_, selected_packet_byte_view_status_text_, selected_packet_byte_view_text_, text, payload_text_, payload_tab_title_, protocol_text_);
}

void PacketDetailsViewModel::setPayloadText(const QString& text) {
    emitIfChanged(!summary_text_.isEmpty() || !summary_layers_.isEmpty() || !packet_byte_view_descriptors_.isEmpty() || !selected_packet_byte_view_text_.isEmpty() || !hex_text_.isEmpty() || !text.isEmpty() || !protocol_text_.isEmpty(), stream_item_details_, details_title_, header_primary_text_, header_secondary_text_, badge_text_, summary_text_, summary_layers_, packet_byte_view_descriptors_, selected_packet_byte_view_id_, selected_packet_byte_view_label_, selected_packet_byte_view_state_, selected_packet_byte_view_available_length_, selected_packet_byte_view_declared_length_, selected_packet_byte_view_status_text_, selected_packet_byte_view_text_, hex_text_, text, payload_tab_title_, protocol_text_);
}

void PacketDetailsViewModel::setPayloadTabTitle(const QString& text) {
    emitIfChanged(!summary_text_.isEmpty() || !summary_layers_.isEmpty() || !packet_byte_view_descriptors_.isEmpty() || !selected_packet_byte_view_text_.isEmpty() || !hex_text_.isEmpty() || !payload_text_.isEmpty() || !protocol_text_.isEmpty(), stream_item_details_, details_title_, header_primary_text_, header_secondary_text_, badge_text_, summary_text_, summary_layers_, packet_byte_view_descriptors_, selected_packet_byte_view_id_, selected_packet_byte_view_label_, selected_packet_byte_view_state_, selected_packet_byte_view_available_length_, selected_packet_byte_view_declared_length_, selected_packet_byte_view_status_text_, selected_packet_byte_view_text_, hex_text_, payload_text_, text, protocol_text_);
}

void PacketDetailsViewModel::setProtocolText(const QString& text) {
    emitIfChanged(!summary_text_.isEmpty() || !summary_layers_.isEmpty() || !packet_byte_view_descriptors_.isEmpty() || !selected_packet_byte_view_text_.isEmpty() || !hex_text_.isEmpty() || !payload_text_.isEmpty() || !text.isEmpty(), stream_item_details_, details_title_, header_primary_text_, header_secondary_text_, badge_text_, summary_text_, summary_layers_, packet_byte_view_descriptors_, selected_packet_byte_view_id_, selected_packet_byte_view_label_, selected_packet_byte_view_state_, selected_packet_byte_view_available_length_, selected_packet_byte_view_declared_length_, selected_packet_byte_view_status_text_, selected_packet_byte_view_text_, hex_text_, payload_text_, payload_tab_title_, text);
}

void PacketDetailsViewModel::emitIfChanged(const bool newHasPacket,
                                           const bool newStreamItemDetails,
                                           const QString& newDetailsTitle,
                                           const QString& newHeaderPrimaryText,
                                           const QString& newHeaderSecondaryText,
                                           const QString& newBadgeText,
                                           const QString& newSummaryText,
                                           const QVariantList& newSummaryLayers,
                                           const QVariantList& newPacketByteViewDescriptors,
                                           const QString& newSelectedPacketByteViewId,
                                           const QString& newSelectedPacketByteViewLabel,
                                           const QString& newSelectedPacketByteViewState,
                                           const qulonglong newSelectedPacketByteViewAvailableLength,
                                           const QVariant& newSelectedPacketByteViewDeclaredLength,
                                           const QString& newSelectedPacketByteViewStatusText,
                                           const QString& newSelectedPacketByteViewText,
                                           const QString& newHexText,
                                           const QString& newPayloadText,
                                           const QString& newPayloadTabTitle,
                                           const QString& newProtocolText) {
    if (has_packet_ == newHasPacket &&
        stream_item_details_ == newStreamItemDetails &&
        details_title_ == newDetailsTitle &&
        header_primary_text_ == newHeaderPrimaryText &&
        header_secondary_text_ == newHeaderSecondaryText &&
        badge_text_ == newBadgeText &&
        summary_text_ == newSummaryText &&
        summary_layers_ == newSummaryLayers &&
        packet_byte_view_descriptors_ == newPacketByteViewDescriptors &&
        selected_packet_byte_view_id_ == newSelectedPacketByteViewId &&
        selected_packet_byte_view_label_ == newSelectedPacketByteViewLabel &&
        selected_packet_byte_view_state_ == newSelectedPacketByteViewState &&
        selected_packet_byte_view_available_length_ == newSelectedPacketByteViewAvailableLength &&
        selected_packet_byte_view_declared_length_ == newSelectedPacketByteViewDeclaredLength &&
        selected_packet_byte_view_status_text_ == newSelectedPacketByteViewStatusText &&
        selected_packet_byte_view_text_ == newSelectedPacketByteViewText &&
        hex_text_ == newHexText &&
        payload_text_ == newPayloadText &&
        payload_tab_title_ == newPayloadTabTitle &&
        protocol_text_ == newProtocolText) {
        return;
    }

    has_packet_ = newHasPacket;
    stream_item_details_ = newStreamItemDetails;
    details_title_ = newDetailsTitle;
    header_primary_text_ = newHeaderPrimaryText;
    header_secondary_text_ = newHeaderSecondaryText;
    badge_text_ = newBadgeText;
    summary_text_ = newSummaryText;
    summary_layers_ = newSummaryLayers;
    packet_byte_view_descriptors_ = newPacketByteViewDescriptors;
    selected_packet_byte_view_id_ = newSelectedPacketByteViewId;
    selected_packet_byte_view_label_ = newSelectedPacketByteViewLabel;
    selected_packet_byte_view_state_ = newSelectedPacketByteViewState;
    selected_packet_byte_view_available_length_ = newSelectedPacketByteViewAvailableLength;
    selected_packet_byte_view_declared_length_ = newSelectedPacketByteViewDeclaredLength;
    selected_packet_byte_view_status_text_ = newSelectedPacketByteViewStatusText;
    selected_packet_byte_view_text_ = newSelectedPacketByteViewText;
    hex_text_ = newHexText;
    payload_text_ = newPayloadText;
    payload_tab_title_ = newPayloadTabTitle;
    protocol_text_ = newProtocolText;
    emit changed();
}

}  // namespace pfl
