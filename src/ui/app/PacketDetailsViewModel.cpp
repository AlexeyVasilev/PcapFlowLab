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

void PacketDetailsViewModel::clear() {
    emitIfChanged(false, {}, {});
}

void PacketDetailsViewModel::setPacketDetailsText(const QString& text) {
    emitIfChanged(!text.isEmpty() || !hex_text_.isEmpty(), text, hex_text_);
}

void PacketDetailsViewModel::setHexText(const QString& text) {
    emitIfChanged(!summary_text_.isEmpty() || !text.isEmpty(), summary_text_, text);
}

void PacketDetailsViewModel::emitIfChanged(const bool newHasPacket,
                                           const QString& newSummaryText,
                                           const QString& newHexText) {
    if (has_packet_ == newHasPacket && summary_text_ == newSummaryText && hex_text_ == newHexText) {
        return;
    }

    has_packet_ = newHasPacket;
    summary_text_ = newSummaryText;
    hex_text_ = newHexText;
    emit changed();
}

}  // namespace pfl
