#include "ui/app/PacketDetailsViewModel.h"

namespace pfl {

PacketDetailsViewModel::PacketDetailsViewModel(QObject* parent)
    : QObject(parent) {
}

bool PacketDetailsViewModel::hasPacket() const noexcept {
    return has_packet_;
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
    emitIfChanged(false, {}, {}, {}, {});
}

void PacketDetailsViewModel::setPacketDetailsText(const QString& text) {
    emitIfChanged(!text.isEmpty() || !hex_text_.isEmpty() || !payload_text_.isEmpty() || !protocol_text_.isEmpty(), text, hex_text_, payload_text_, protocol_text_);
}

void PacketDetailsViewModel::setHexText(const QString& text) {
    emitIfChanged(!summary_text_.isEmpty() || !text.isEmpty() || !payload_text_.isEmpty() || !protocol_text_.isEmpty(), summary_text_, text, payload_text_, protocol_text_);
}

void PacketDetailsViewModel::setPayloadText(const QString& text) {
    emitIfChanged(!summary_text_.isEmpty() || !hex_text_.isEmpty() || !text.isEmpty() || !protocol_text_.isEmpty(), summary_text_, hex_text_, text, protocol_text_);
}

void PacketDetailsViewModel::setProtocolText(const QString& text) {
    emitIfChanged(!summary_text_.isEmpty() || !hex_text_.isEmpty() || !payload_text_.isEmpty() || !text.isEmpty(), summary_text_, hex_text_, payload_text_, text);
}

void PacketDetailsViewModel::emitIfChanged(const bool newHasPacket,
                                           const QString& newSummaryText,
                                           const QString& newHexText,
                                           const QString& newPayloadText,
                                           const QString& newProtocolText) {
    if (has_packet_ == newHasPacket &&
        summary_text_ == newSummaryText &&
        hex_text_ == newHexText &&
        payload_text_ == newPayloadText &&
        protocol_text_ == newProtocolText) {
        return;
    }

    has_packet_ = newHasPacket;
    summary_text_ = newSummaryText;
    hex_text_ = newHexText;
    payload_text_ = newPayloadText;
    protocol_text_ = newProtocolText;
    emit changed();
}

}  // namespace pfl
