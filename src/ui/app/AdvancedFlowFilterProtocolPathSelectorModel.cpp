#include "ui/app/AdvancedFlowFilterProtocolPathSelectorModel.h"

#include <algorithm>

namespace pfl {

namespace {

ProtocolPathStatisticsMode protocol_path_selector_mode_from_int(const int mode) noexcept {
    switch (mode) {
    case static_cast<int>(ProtocolPathStatisticsMode::identity_tree):
        return ProtocolPathStatisticsMode::identity_tree;
    case static_cast<int>(ProtocolPathStatisticsMode::terminal_paths):
        return ProtocolPathStatisticsMode::terminal_paths;
    case static_cast<int>(ProtocolPathStatisticsMode::kind_overview):
    default:
        return ProtocolPathStatisticsMode::kind_overview;
    }
}

bool protocol_path_has_identifiers(const std::vector<LayerKey>& layers) noexcept {
    return std::any_of(layers.begin(), layers.end(), [](const LayerKey& layer) {
        return layer.identifier.kind != ProtocolLayerIdentifierKind::none;
    });
}

std::vector<LayerKey> protocol_path_layers_from_predicate(
    const std::vector<session_detail::AdvancedFlowFilterProtocolLayerPredicate>& layers
) {
    std::vector<LayerKey> converted {};
    converted.reserve(layers.size());
    for (const auto& layer : layers) {
        converted.push_back(LayerKey {
            .kind = layer.kind,
            .identifier = layer.identifier.value_or(ProtocolLayerIdentifier {}),
        });
    }
    return converted;
}

std::vector<session_detail::AdvancedFlowFilterProtocolLayerPredicate> protocol_path_layers_to_predicate(
    const std::vector<LayerKey>& layers
) {
    std::vector<session_detail::AdvancedFlowFilterProtocolLayerPredicate> converted {};
    converted.reserve(layers.size());
    for (const auto& layer : layers) {
        converted.push_back(session_detail::AdvancedFlowFilterProtocolLayerPredicate {
            .kind = layer.kind,
            .identifier = layer.identifier.kind == ProtocolLayerIdentifierKind::none
                ? std::nullopt
                : std::optional<ProtocolLayerIdentifier> {layer.identifier},
        });
    }
    return converted;
}

ProtocolPathStatisticsMode selector_mode_for_predicate(
    const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate
) noexcept {
    if (predicate.match_kind == session_detail::AdvancedFlowFilterProtocolPathMatchKind::exact_path) {
        return ProtocolPathStatisticsMode::terminal_paths;
    }
    return protocol_path_has_identifiers(protocol_path_layers_from_predicate(predicate.layers))
        ? ProtocolPathStatisticsMode::identity_tree
        : ProtocolPathStatisticsMode::kind_overview;
}

}  // namespace

AdvancedFlowFilterProtocolPathSelectorModel::AdvancedFlowFilterProtocolPathSelectorModel(QObject* parent)
    : QObject(parent)
    , stats_model_(this) {}

int AdvancedFlowFilterProtocolPathSelectorModel::revision() const noexcept {
    return revision_;
}

int AdvancedFlowFilterProtocolPathSelectorModel::mode() const noexcept {
    return static_cast<int>(mode_);
}

QObject* AdvancedFlowFilterProtocolPathSelectorModel::statsModel() noexcept {
    return &stats_model_;
}

bool AdvancedFlowFilterProtocolPathSelectorModel::hasCapture() const noexcept {
    return session_ != nullptr && session_->has_capture();
}

bool AdvancedFlowFilterProtocolPathSelectorModel::selectionAvailable() const noexcept {
    return stats_model_.hasSelectedNode();
}

QString AdvancedFlowFilterProtocolPathSelectorModel::statusText() const {
    return status_text_;
}

void AdvancedFlowFilterProtocolPathSelectorModel::setCaptureSession(const CaptureSession* session) {
    if (session_ == session) {
        refreshSummary(true);
        return;
    }

    session_ = session;
    refreshSummary(false);
}

void AdvancedFlowFilterProtocolPathSelectorModel::selectPredicate(
    const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate
) {
    const auto next_mode = selector_mode_for_predicate(predicate);
    const bool preserve_selection = next_mode == mode_;
    mode_ = next_mode;
    refreshSummary(preserve_selection);
    const auto predicate_layers = protocol_path_layers_from_predicate(predicate.layers);

    for (const auto& row : summary_.rows) {
        if (row.path.layers() == predicate_layers) {
            stats_model_.selectNode(row.node_id);
            emitStateChanged();
            return;
        }
    }

    stats_model_.clearSelection();
    emitStateChanged();
}

std::optional<session_detail::AdvancedFlowFilterProtocolPathPredicate>
AdvancedFlowFilterProtocolPathSelectorModel::selectedPredicate() const {
    const auto* row = selectedRow();
    if (row == nullptr) {
        return std::nullopt;
    }

    return session_detail::AdvancedFlowFilterProtocolPathPredicate {
        .match_kind = mode_ == ProtocolPathStatisticsMode::terminal_paths
            ? session_detail::AdvancedFlowFilterProtocolPathMatchKind::exact_path
            : session_detail::AdvancedFlowFilterProtocolPathMatchKind::path_prefix,
        .layers = protocol_path_layers_to_predicate(row->path.layers()),
    };
}

void AdvancedFlowFilterProtocolPathSelectorModel::setMode(const int mode) {
    const auto next_mode = protocol_path_selector_mode_from_int(mode);
    if (mode_ == next_mode) {
        return;
    }

    mode_ = next_mode;
    refreshSummary(false);
}

void AdvancedFlowFilterProtocolPathSelectorModel::selectNode(const qulonglong nodeId) {
    stats_model_.selectNode(nodeId);
    emitStateChanged();
}

void AdvancedFlowFilterProtocolPathSelectorModel::clearSelection() {
    if (!stats_model_.hasSelectedNode()) {
        return;
    }

    stats_model_.clearSelection();
    emitStateChanged();
}

void AdvancedFlowFilterProtocolPathSelectorModel::refreshSummary(const bool preserveSelection) {
    const auto selected_node_id = preserveSelection && stats_model_.hasSelectedNode()
        ? static_cast<std::uint64_t>(stats_model_.selectedNodeId())
        : kInvalidProtocolPathStatisticsNodeId;

    if (!hasCapture()) {
        summary_ = {};
        stats_model_.clear();
        status_text_ = QStringLiteral("No capture loaded.");
        emitStateChanged();
        return;
    }

    summary_ = session_->protocol_path_summary(mode_);
    stats_model_.refresh(summary_);
    if (stats_model_.canExpand()) {
        stats_model_.expandAll();
    }

    if (selected_node_id != kInvalidProtocolPathStatisticsNodeId) {
        stats_model_.selectNode(selected_node_id);
    }

    status_text_ = summary_.rows.empty()
        ? QStringLiteral("No Protocol Path rows are available for the current capture.")
        : QString {};
    emitStateChanged();
}

void AdvancedFlowFilterProtocolPathSelectorModel::emitStateChanged() {
    ++revision_;
    emit stateChanged();
}

const ProtocolPathStatisticsRow* AdvancedFlowFilterProtocolPathSelectorModel::selectedRow() const noexcept {
    if (!stats_model_.hasSelectedNode()) {
        return nullptr;
    }

    const auto selected_node_id = static_cast<std::uint64_t>(stats_model_.selectedNodeId());
    const auto it = std::find_if(summary_.rows.begin(), summary_.rows.end(), [&](const auto& row) {
        return row.node_id == selected_node_id;
    });
    return it == summary_.rows.end() ? nullptr : &*it;
}

}  // namespace pfl
