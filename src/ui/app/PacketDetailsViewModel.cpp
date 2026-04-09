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

const QString& PacketDetailsViewModel::hexText() const noexcept {
    return hex_text_;
}

const QString& PacketDetailsViewModel::payloadText() const noexcept {
    return payload_text_;
}

const QString& PacketDetailsViewModel::protocolText() const noexcept {
    return protocol_text_;
}

void PacketDetailsViewModel::clear() {
    emitIfChanged(false, false, QStringLiteral("Packet Details"), {}, {}, {}, {}, {}, {}, {});
}

void PacketDetailsViewModel::setDetailsTitle(const QString& text) {
    emitIfChanged(has_packet_, stream_item_details_, text, header_primary_text_, header_secondary_text_, badge_text_, summary_text_, hex_text_, payload_text_, protocol_text_);
}

void PacketDetailsViewModel::setStreamItemPresentation(const QString& primaryText, const QString& secondaryText, const QString& badgeText) {
    emitIfChanged(has_packet_, true, details_title_, primaryText, secondaryText, badgeText, summary_text_, hex_text_, payload_text_, protocol_text_);
}

void PacketDetailsViewModel::clearStreamItemPresentation() {
    emitIfChanged(has_packet_, false, details_title_, {}, {}, {}, summary_text_, hex_text_, payload_text_, protocol_text_);
}

void PacketDetailsViewModel::setPacketDetailsText(const QString& text) {
    emitIfChanged(!text.isEmpty() || !hex_text_.isEmpty() || !payload_text_.isEmpty() || !protocol_text_.isEmpty(), stream_item_details_, details_title_, header_primary_text_, header_secondary_text_, badge_text_, text, hex_text_, payload_text_, protocol_text_);
}

void PacketDetailsViewModel::setHexText(const QString& text) {
    emitIfChanged(!summary_text_.isEmpty() || !text.isEmpty() || !payload_text_.isEmpty() || !protocol_text_.isEmpty(), stream_item_details_, details_title_, header_primary_text_, header_secondary_text_, badge_text_, summary_text_, text, payload_text_, protocol_text_);
}

void PacketDetailsViewModel::setPayloadText(const QString& text) {
    emitIfChanged(!summary_text_.isEmpty() || !hex_text_.isEmpty() || !text.isEmpty() || !protocol_text_.isEmpty(), stream_item_details_, details_title_, header_primary_text_, header_secondary_text_, badge_text_, summary_text_, hex_text_, text, protocol_text_);
}

void PacketDetailsViewModel::setProtocolText(const QString& text) {
    emitIfChanged(!summary_text_.isEmpty() || !hex_text_.isEmpty() || !payload_text_.isEmpty() || !text.isEmpty(), stream_item_details_, details_title_, header_primary_text_, header_secondary_text_, badge_text_, summary_text_, hex_text_, payload_text_, text);
}

void PacketDetailsViewModel::emitIfChanged(const bool newHasPacket,
                                           const bool newStreamItemDetails,
                                           const QString& newDetailsTitle,
                                           const QString& newHeaderPrimaryText,
                                           const QString& newHeaderSecondaryText,
                                           const QString& newBadgeText,
                                           const QString& newSummaryText,
                                           const QString& newHexText,
                                           const QString& newPayloadText,
                                           const QString& newProtocolText) {
    if (has_packet_ == newHasPacket &&
        stream_item_details_ == newStreamItemDetails &&
        details_title_ == newDetailsTitle &&
        header_primary_text_ == newHeaderPrimaryText &&
        header_secondary_text_ == newHeaderSecondaryText &&
        badge_text_ == newBadgeText &&
        summary_text_ == newSummaryText &&
        hex_text_ == newHexText &&
        payload_text_ == newPayloadText &&
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
    hex_text_ = newHexText;
    payload_text_ = newPayloadText;
    protocol_text_ = newProtocolText;
    emit changed();
}

}  // namespace pfl
