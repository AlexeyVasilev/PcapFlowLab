#include "ui/app/StreamListModel.h"

namespace pfl {

namespace {

QString format_source_packets_text(
    const StreamItemRow& row,
    const std::map<std::uint64_t, std::uint64_t>& flowPacketNumbers
) {
    QStringList packetNumbers {};
    packetNumbers.reserve(static_cast<qsizetype>(row.packet_indices.size()));

    bool used_flow_numbers = true;
    for (const auto packet_index : row.packet_indices) {
        const auto flowIt = flowPacketNumbers.find(packet_index);
        if (flowIt == flowPacketNumbers.end()) {
            used_flow_numbers = false;
            break;
        }
        packetNumbers.push_back(QStringLiteral("#%1").arg(flowIt->second));
    }

    if (!used_flow_numbers) {
        packetNumbers.clear();
        packetNumbers.reserve(static_cast<qsizetype>(row.packet_indices.size()));
        for (const auto packet_index : row.packet_indices) {
            packetNumbers.push_back(QStringLiteral("#%1").arg(packet_index));
        }
    }

    if (packetNumbers.isEmpty()) {
        return row.packet_count == 1U
            ? QStringLiteral("1 packet")
            : QStringLiteral("%1 packets").arg(row.packet_count);
    }

    return packetNumbers.size() == 1
        ? QStringLiteral("packet %1").arg(packetNumbers.join(QString {}))
        : QStringLiteral("packets %1").arg(packetNumbers.join(QStringLiteral(",")));
}

}  // namespace

StreamListModel::StreamListModel(QObject* parent)
    : QAbstractListModel(parent) {
}

int StreamListModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid()) {
        return 0;
    }

    return static_cast<int>(items_.size());
}

QVariant StreamListModel::data(const QModelIndex& index, const int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= rowCount()) {
        return {};
    }

    const Item& item = items_[static_cast<std::size_t>(index.row())];
    switch (role) {
    case StreamItemIndexRole:
        return QVariant::fromValue(item.stream_item_index);
    case DirectionTextRole:
        return item.direction_text;
    case LabelRole:
        return item.label;
    case ByteCountRole:
        return item.byte_count;
    case PacketCountRole:
        return item.packet_count;
    case SourcePacketsTextRole:
        return item.source_packets_text;
    default:
        return {};
    }
}

QHash<int, QByteArray> StreamListModel::roleNames() const {
    return {
        {StreamItemIndexRole, "streamItemIndex"},
        {DirectionTextRole, "directionText"},
        {LabelRole, "label"},
        {ByteCountRole, "byteCount"},
        {PacketCountRole, "packetCount"},
        {SourcePacketsTextRole, "sourcePacketsText"},
    };
}

void StreamListModel::refresh(const std::vector<StreamItemRow>& rows, const std::map<std::uint64_t, std::uint64_t>& flowPacketNumbers) {
    beginResetModel();
    items_.clear();
    items_.reserve(rows.size());

    for (const auto& row : rows) {
        items_.push_back(Item {
            .stream_item_index = static_cast<qulonglong>(row.stream_item_index),
            .direction_text = QString::fromStdString(row.direction_text),
            .label = QString::fromStdString(row.label),
            .byte_count = row.byte_count,
            .packet_count = row.packet_count,
            .source_packets_text = format_source_packets_text(row, flowPacketNumbers),
        });
    }

    endResetModel();
}

void StreamListModel::append(const std::vector<StreamItemRow>& rows, const std::map<std::uint64_t, std::uint64_t>& flowPacketNumbers) {
    if (rows.empty()) {
        return;
    }

    const auto beginIndex = static_cast<int>(items_.size());
    const auto endIndex = beginIndex + static_cast<int>(rows.size()) - 1;
    beginInsertRows(QModelIndex {}, beginIndex, endIndex);
    items_.reserve(items_.size() + rows.size());

    for (const auto& row : rows) {
        items_.push_back(Item {
            .stream_item_index = static_cast<qulonglong>(row.stream_item_index),
            .direction_text = QString::fromStdString(row.direction_text),
            .label = QString::fromStdString(row.label),
            .byte_count = row.byte_count,
            .packet_count = row.packet_count,
            .source_packets_text = format_source_packets_text(row, flowPacketNumbers),
        });
    }

    endInsertRows();
}

void StreamListModel::clear() {
    refresh({});
}

}  // namespace pfl
