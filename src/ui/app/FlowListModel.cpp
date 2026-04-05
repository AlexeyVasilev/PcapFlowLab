#include "ui/app/FlowListModel.h"

#include <algorithm>
#include <map>

namespace pfl {

namespace {

QString to_qstring(const std::string& value) {
    return QString::fromStdString(value);
}

QString format_protocol_hint(const std::string& value) {
    const auto hint = QString::fromStdString(value);
    if (hint == QStringLiteral("possible_tls")) {
        return QStringLiteral("Possible TLS");
    }
    if (hint == QStringLiteral("possible_quic")) {
        return QStringLiteral("Possible QUIC");
    }

    return hint.toUpper();
}

QString format_fragmented_packet_count(const FlowListModel::Item& item) {
    return item.fragmented_packets == 0 ? QString {} : QString::number(item.fragmented_packets);
}

bool contains_text(const FlowListModel::Item& item, const QString& filter) {
    const bool matches_fragment_text = item.has_fragmented_packets && filter.contains(QStringLiteral("frag"), Qt::CaseInsensitive);
    return item.family.contains(filter, Qt::CaseInsensitive)
        || item.protocol.contains(filter, Qt::CaseInsensitive)
        || item.protocol_hint.contains(filter, Qt::CaseInsensitive)
        || item.service_hint.contains(filter, Qt::CaseInsensitive)
        || item.address_a.contains(filter, Qt::CaseInsensitive)
        || item.address_b.contains(filter, Qt::CaseInsensitive)
        || item.endpoint_a.contains(filter, Qt::CaseInsensitive)
        || item.endpoint_b.contains(filter, Qt::CaseInsensitive)
        || QString::number(item.port_a).contains(filter, Qt::CaseInsensitive)
        || QString::number(item.port_b).contains(filter, Qt::CaseInsensitive)
        || QString::number(item.fragmented_packets).contains(filter, Qt::CaseInsensitive)
        || matches_fragment_text;
}

bool less_than(const FlowListModel::Item& left, const FlowListModel::Item& right, const FlowListModel::SortKey key) {
    switch (key) {
    case FlowListModel::SortKey::index:
        return left.flow_index < right.flow_index;
    case FlowListModel::SortKey::family:
        return left.family < right.family;
    case FlowListModel::SortKey::protocol:
        if (left.protocol != right.protocol) {
            return left.protocol < right.protocol;
        }
        return left.flow_index < right.flow_index;
    case FlowListModel::SortKey::protocol_hint:
        if (left.protocol_hint != right.protocol_hint) {
            return left.protocol_hint < right.protocol_hint;
        }
        return left.flow_index < right.flow_index;
    case FlowListModel::SortKey::service_hint:
        if (left.service_hint != right.service_hint) {
            return left.service_hint < right.service_hint;
        }
        return left.flow_index < right.flow_index;
    case FlowListModel::SortKey::fragmented_packets:
        if (left.fragmented_packets != right.fragmented_packets) {
            return left.fragmented_packets < right.fragmented_packets;
        }
        return left.flow_index < right.flow_index;
    case FlowListModel::SortKey::address_a:
        if (left.address_a != right.address_a) {
            return left.address_a < right.address_a;
        }
        return left.port_a < right.port_a;
    case FlowListModel::SortKey::port_a:
        if (left.port_a != right.port_a) {
            return left.port_a < right.port_a;
        }
        return left.address_a < right.address_a;
    case FlowListModel::SortKey::address_b:
        if (left.address_b != right.address_b) {
            return left.address_b < right.address_b;
        }
        return left.port_b < right.port_b;
    case FlowListModel::SortKey::port_b:
        if (left.port_b != right.port_b) {
            return left.port_b < right.port_b;
        }
        return left.address_b < right.address_b;
    case FlowListModel::SortKey::packets:
        if (left.packets != right.packets) {
            return left.packets < right.packets;
        }
        return left.flow_index < right.flow_index;
    case FlowListModel::SortKey::bytes:
        if (left.bytes != right.bytes) {
            return left.bytes < right.bytes;
        }
        return left.flow_index < right.flow_index;
    }

    return left.flow_index < right.flow_index;
}

}  // namespace

FlowListModel::FlowListModel(QObject* parent)
    : QAbstractListModel(parent) {
}

int FlowListModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid()) {
        return 0;
    }

    return static_cast<int>(visible_items_.size());
}

QVariant FlowListModel::data(const QModelIndex& index, const int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= rowCount()) {
        return {};
    }

    const Item& item = visible_items_[static_cast<std::size_t>(index.row())];
    switch (role) {
    case FlowIndexRole:
        return item.flow_index;
    case CheckedRole:
        return item.checked;
    case FamilyRole:
        return item.family;
    case ProtocolRole:
        return item.protocol;
    case ProtocolHintRole:
        return item.protocol_hint;
    case ServiceHintRole:
        return item.service_hint;
    case HasFragmentedPacketsRole:
        return item.has_fragmented_packets;
    case FragmentedPacketCountRole:
        return format_fragmented_packet_count(item);
    case AddressARole:
        return item.address_a;
    case PortARole:
        return item.port_a;
    case AddressBRole:
        return item.address_b;
    case PortBRole:
        return item.port_b;
    case PacketsRole:
        return QString::number(item.packets);
    case BytesRole:
        return QString::number(item.bytes);
    default:
        return {};
    }
}

QHash<int, QByteArray> FlowListModel::roleNames() const {
    return {
        {FlowIndexRole, "flowIndex"},
        {CheckedRole, "flowChecked"},
        {FamilyRole, "family"},
        {ProtocolRole, "protocol"},
        {ProtocolHintRole, "protocolHint"},
        {ServiceHintRole, "serviceHint"},
        {HasFragmentedPacketsRole, "hasFragmentedPackets"},
        {FragmentedPacketCountRole, "fragmentedPacketCount"},
        {AddressARole, "addressA"},
        {PortARole, "portA"},
        {AddressBRole, "addressB"},
        {PortBRole, "portB"},
        {PacketsRole, "packets"},
        {BytesRole, "bytes"},
    };
}

int FlowListModel::rowForFlowIndex(const int flowIndex) const noexcept {
    for (std::size_t row = 0; row < visible_items_.size(); ++row) {
        if (visible_items_[row].flow_index == flowIndex) {
            return static_cast<int>(row);
        }
    }

    return -1;
}

void FlowListModel::setFlowChecked(const int flowIndex, const bool checked) {
    auto allItemIt = std::find_if(all_items_.begin(), all_items_.end(), [flowIndex](const Item& item) {
        return item.flow_index == flowIndex;
    });
    if (allItemIt == all_items_.end() || allItemIt->checked == checked) {
        return;
    }

    allItemIt->checked = checked;

    auto visibleItemIt = std::find_if(visible_items_.begin(), visible_items_.end(), [flowIndex](const Item& item) {
        return item.flow_index == flowIndex;
    });
    if (visibleItemIt != visible_items_.end()) {
        visibleItemIt->checked = checked;
        const auto row = static_cast<int>(std::distance(visible_items_.begin(), visibleItemIt));
        const QModelIndex modelIndex = index(row, 0);
        emit dataChanged(modelIndex, modelIndex, {CheckedRole});
    }

    emit checkedFlowsChanged();
}

bool FlowListModel::isFlowChecked(const int flowIndex) const noexcept {
    const auto itemIt = std::find_if(all_items_.begin(), all_items_.end(), [flowIndex](const Item& item) {
        return item.flow_index == flowIndex;
    });
    return itemIt != all_items_.end() && itemIt->checked;
}

void FlowListModel::clearCheckedFlows() {
    if (all_items_.empty()) {
        return;
    }

    bool changed = false;
    for (auto& item : all_items_) {
        if (!item.checked) {
            continue;
        }
        item.checked = false;
        changed = true;
    }

    if (!changed) {
        return;
    }

    for (auto& item : visible_items_) {
        item.checked = false;
    }

    if (!visible_items_.empty()) {
        emit dataChanged(index(0, 0), index(rowCount() - 1, 0), {CheckedRole});
    }
    emit checkedFlowsChanged();
}

int FlowListModel::checkedFlowCount() const noexcept {
    return static_cast<int>(std::count_if(all_items_.begin(), all_items_.end(), [](const Item& item) {
        return item.checked;
    }));
}

void FlowListModel::refresh(const std::vector<FlowRow>& rows) {
    std::map<int, bool> checkedByFlowIndex {};
    for (const auto& item : all_items_) {
        if (item.checked) {
            checkedByFlowIndex[item.flow_index] = true;
        }
    }

    all_items_.clear();
    all_items_.reserve(rows.size());

    for (const auto& row : rows) {
        const int flowIndex = static_cast<int>(row.index);
        all_items_.push_back(Item {
            .flow_index = flowIndex,
            .checked = checkedByFlowIndex.contains(flowIndex),
            .family = (row.family == FlowAddressFamily::ipv4) ? "IPv4" : "IPv6",
            .protocol = to_qstring(row.protocol_text),
            .protocol_hint = format_protocol_hint(row.protocol_hint),
            .service_hint = to_qstring(row.service_hint),
            .has_fragmented_packets = row.has_fragmented_packets,
            .fragmented_packets = static_cast<qulonglong>(row.fragmented_packet_count),
            .address_a = to_qstring(row.address_a),
            .port_a = row.port_a,
            .endpoint_a = to_qstring(row.endpoint_a),
            .address_b = to_qstring(row.address_b),
            .port_b = row.port_b,
            .endpoint_b = to_qstring(row.endpoint_b),
            .packets = static_cast<qulonglong>(row.packet_count),
            .bytes = static_cast<qulonglong>(row.total_bytes),
        });
    }

    rebuildVisibleItems();
    emit checkedFlowsChanged();
}

void FlowListModel::clear() {
    if (all_items_.empty() && visible_items_.empty()) {
        return;
    }

    const bool hadCheckedFlows = checkedFlowCount() > 0;
    all_items_.clear();
    rebuildVisibleItems();

    if (hadCheckedFlows) {
        emit checkedFlowsChanged();
    }
}

void FlowListModel::resetViewState() {
    filter_text_.clear();
    sort_key_ = SortKey::index;
    sort_ascending_ = true;
    rebuildVisibleItems();
}

void FlowListModel::setFilterText(const QString& text) {
    if (filter_text_ == text) {
        return;
    }

    filter_text_ = text;
    rebuildVisibleItems();
}

void FlowListModel::setSortKey(const SortKey key) {
    if (sort_key_ == key) {
        return;
    }

    sort_key_ = key;
    rebuildVisibleItems();
}

void FlowListModel::setSortAscending(const bool ascending) noexcept {
    if (sort_ascending_ == ascending) {
        return;
    }

    sort_ascending_ = ascending;
    rebuildVisibleItems();
}

const QString& FlowListModel::filterText() const noexcept {
    return filter_text_;
}

FlowListModel::SortKey FlowListModel::sortKey() const noexcept {
    return sort_key_;
}

bool FlowListModel::sortAscending() const noexcept {
    return sort_ascending_;
}

bool FlowListModel::containsFlowIndex(const int flowIndex) const noexcept {
    return std::any_of(visible_items_.begin(), visible_items_.end(), [flowIndex](const Item& item) {
        return item.flow_index == flowIndex;
    });
}

int FlowListModel::totalFlowCount() const noexcept {
    return static_cast<int>(all_items_.size());
}

std::vector<int> FlowListModel::checkedFlowIndices() const {
    std::vector<int> flowIndices {};
    flowIndices.reserve(all_items_.size());

    for (const auto& item : all_items_) {
        if (item.checked) {
            flowIndices.push_back(item.flow_index);
        }
    }

    return flowIndices;
}

std::vector<int> FlowListModel::uncheckedFlowIndices() const {
    std::vector<int> flowIndices {};
    flowIndices.reserve(all_items_.size());

    for (const auto& item : all_items_) {
        if (!item.checked) {
            flowIndices.push_back(item.flow_index);
        }
    }

    return flowIndices;
}

void FlowListModel::setServiceHintForFlowIndex(const int flowIndex, const QString& serviceHint) {
    auto itemIt = std::find_if(all_items_.begin(), all_items_.end(), [flowIndex](const Item& item) {
        return item.flow_index == flowIndex;
    });
    if (itemIt == all_items_.end() || itemIt->service_hint == serviceHint) {
        return;
    }

    itemIt->service_hint = serviceHint;
    rebuildVisibleItems();
}

void FlowListModel::rebuildVisibleItems() {
    beginResetModel();
    visible_items_.clear();
    visible_items_.reserve(all_items_.size());

    for (const auto& item : all_items_) {
        if (filter_text_.isEmpty() || contains_text(item, filter_text_)) {
            visible_items_.push_back(item);
        }
    }

    std::sort(visible_items_.begin(), visible_items_.end(), [this](const Item& left, const Item& right) {
        const bool isLess = less_than(left, right, sort_key_);
        const bool isGreater = less_than(right, left, sort_key_);

        if (!isLess && !isGreater) {
            return left.flow_index < right.flow_index;
        }

        return sort_ascending_ ? isLess : isGreater;
    });

    endResetModel();
}

}  // namespace pfl
