#include "ui/app/MainController.h"

#include "app/frontend/FrontendStatisticsOverview.h"
#include "app/session/AdvancedFlowFilterFormat.h"
#include "app/session/ByteExport.h"
#include "app/session/SelectedFlowPacketSemantics.h"
#include "app/session/SelectedPacketBytePresentation.h"
#include "app/session/ProtocolPathPresentation.h"
#include "app/session/SupportedProtocolCatalog.h"
#include "app/session/SessionFlowHelpers.h"
#include "app/session/SessionFormatting.h"
#include "app/session/SelectedPacketSummaryPreparation.h"
#include "core/decode/PacketDecodeSupport.h"
#include "core/services/HexDumpService.h"
#include "core/services/PacketPayloadService.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <span>
#include <type_traits>

#include <QClipboard>
#include <QCoreApplication>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QGuiApplication>
#include <QHostAddress>
#include <QMessageBox>
#include <QPushButton>
#include <QSaveFile>
#include <QStringList>
#include <QThread>
#include <QTimer>
#include <QVariantMap>

#include "../../../core/open_context.h"
namespace pfl {

namespace {

constexpr qulonglong kInvalidPacketSelection = std::numeric_limits<qulonglong>::max();
constexpr qulonglong kInvalidStreamSelection = std::numeric_limits<qulonglong>::max();
constexpr int kFlowTabIndex = 0;
constexpr int kAnalysisTabIndex = 1;
constexpr int kStatsTabIndex = 2;
constexpr int kSettingsTabIndex = 3;
constexpr int kSmartExportFlowScopeCurrentFlow = 0;
constexpr int kSmartExportFlowScopeSelectedFlows = 1;
constexpr int kSmartExportFlowScopeUnselectedFlows = 2;
constexpr int kSmartExportFlowScopeAllFlows = 3;
constexpr int kSmartExportFlowScopeMatchingCurrentFilter = 4;
constexpr int kSmartExportFlowScopeNotMatchingCurrentFilter = 5;
constexpr int kSmartExportFlowScopeUnrecognizedPackets = 6;
constexpr int kSmartExportOutputModeSingleFile = 0;
constexpr int kSmartExportOutputModeSeparateFilePerFlow = 1;
constexpr int kSmartExportBaseModeAllPackets = 0;
constexpr int kSmartExportBaseModeFirstNPackets = 1;
constexpr int kSmartExportBaseModeFirstMOriginalBytes = 2;
constexpr int kProtocolPathStatisticsModeKindOverview = 0;
constexpr int kProtocolPathStatisticsModeIdentityTree = 1;
constexpr int kProtocolPathStatisticsModeTerminalPaths = 2;
constexpr std::size_t kTopSummaryLimit = 5U;
constexpr std::size_t kInitialPacketRows = 30U;
constexpr std::size_t kPacketRowBatchSize = 30U;
constexpr std::size_t kInitialStreamItems = 15U;
constexpr std::size_t kStreamItemBatchSize = 15U;
constexpr std::size_t kInitialStreamPacketBudget = 30U;
constexpr std::size_t kStreamPacketBatchSize = 30U;
constexpr int kSessionApplyOverlayDelayMs = 40;

QString sanitize_export_filename_component(QString text) {
    text = text.trimmed();
    if (text.isEmpty()) {
        return QStringLiteral("bytes");
    }

    for (QChar& character : text) {
        if (character.isLetterOrNumber()) {
            character = character.toLower();
        } else {
            character = QChar::fromLatin1('-');
        }
    }

    while (text.contains(QStringLiteral("--"))) {
        text.replace(QStringLiteral("--"), QStringLiteral("-"));
    }
    while (text.startsWith(QLatin1Char('-'))) {
        text.remove(0, 1);
    }
    while (text.endsWith(QLatin1Char('-'))) {
        text.chop(1);
    }
    return text.isEmpty() ? QStringLiteral("bytes") : text;
}

QString format_rule_count_text(const std::size_t count) {
    return count == 1U
        ? QStringLiteral("1 rule")
        : QStringLiteral("%1 rules").arg(QString::number(count));
}

bool is_advanced_filter_status_text(const QString& text) {
    return text.startsWith(QStringLiteral("Advanced filter"));
}

bool build_protocol_path_candidate_flow_indices(
    const std::vector<int>& protocol_path_flow_indices,
    std::optional<std::vector<std::size_t>>& out_candidate_flow_indices,
    std::vector<int>* out_canonical_flow_indices = nullptr
) {
    out_candidate_flow_indices.emplace();
    out_candidate_flow_indices->reserve(protocol_path_flow_indices.size());
    if (out_canonical_flow_indices != nullptr) {
        out_canonical_flow_indices->reserve(protocol_path_flow_indices.size());
    }

    for (const auto flow_index : protocol_path_flow_indices) {
        if (flow_index < 0) {
            out_candidate_flow_indices.reset();
            if (out_canonical_flow_indices != nullptr) {
                out_canonical_flow_indices->clear();
            }
            return false;
        }
        out_candidate_flow_indices->push_back(static_cast<std::size_t>(flow_index));
        if (out_canonical_flow_indices != nullptr) {
            out_canonical_flow_indices->push_back(flow_index);
        }
    }

    if (out_canonical_flow_indices != nullptr) {
        std::sort(out_canonical_flow_indices->begin(), out_canonical_flow_indices->end());
        out_canonical_flow_indices->erase(
            std::unique(out_canonical_flow_indices->begin(), out_canonical_flow_indices->end()),
            out_canonical_flow_indices->end()
        );
    }
    return true;
}

QString format_advanced_filter_application_error(const session_detail::AdvancedFlowQueryResult& query_result) {
    QString text = QStringLiteral("Advanced filter could not be applied to the current capture or index.");
    if (query_result.compile_issue.has_value() && !query_result.compile_issue->category.empty()) {
        text += QStringLiteral(" Category: %1").arg(QString::fromStdString(query_result.compile_issue->category));
        if (query_result.compile_issue->predicate_index.has_value()) {
            text += QStringLiteral(" #%1").arg(QString::number(*query_result.compile_issue->predicate_index + 1U));
        }
        text += QLatin1Char('.');
    }
    return text;
}

QString advanced_filter_source_stem_text(const std::filesystem::path& path) {
    const auto stem = path.stem().wstring();
    if (!stem.empty()) {
        return QString::fromStdWString(stem);
    }

    const auto filename = path.filename().wstring();
    return filename.empty() ? QStringLiteral("Custom filter") : QString::fromStdWString(filename);
}

QString format_advanced_filter_text_parse_error(
    const session_detail::AdvancedFlowFilterTextParseResult& parse_result,
    const std::filesystem::path& path
) {
    const QString file_name = QString::fromStdWString(path.filename().wstring());
    if (!parse_result.issue.has_value()) {
        return QStringLiteral("Failed to open advanced filter file %1.").arg(file_name);
    }

    const auto& issue = *parse_result.issue;
    QString location = QStringLiteral("line %1").arg(QString::number(issue.line));
    if (issue.column.has_value()) {
        location += QStringLiteral(", column %1").arg(QString::number(*issue.column));
    }

    QString message = QString::fromStdString(issue.message);
    if (message.isEmpty()) {
        message = QStringLiteral("Invalid advanced filter text.");
    }

    return QStringLiteral("Failed to open advanced filter file %1 at %2: %3")
        .arg(file_name, location, message);
}

QString format_advanced_filter_write_error(const std::filesystem::path& path, const QString& error_text) {
    const QString file_name = QString::fromStdWString(path.filename().wstring());
    if (error_text.isEmpty()) {
        return QStringLiteral("Failed to save advanced filter file %1.").arg(file_name);
    }
    return QStringLiteral("Failed to save advanced filter file %1: %2").arg(file_name, error_text);
}

QString format_advanced_filter_read_error(const std::filesystem::path& path, const QString& error_text) {
    const QString file_name = QString::fromStdWString(path.filename().wstring());
    if (error_text.isEmpty()) {
        return QStringLiteral("Failed to read advanced filter file %1.").arg(file_name);
    }
    return QStringLiteral("Failed to read advanced filter file %1: %2").arg(file_name, error_text);
}

QString format_advanced_filter_file_too_large_error(const std::filesystem::path& path) {
    const QString file_name = QString::fromStdWString(path.filename().wstring());
    return QStringLiteral("Failed to open advanced filter file %1: file is too large (maximum 1 MiB).")
        .arg(file_name);
}

struct AdvancedFlowFilterFileReadResult final {
    enum class Status : std::uint8_t {
        ok = 0,
        read_failed,
        too_large,
    };

    Status status {Status::ok};
    QByteArray bytes {};
};

AdvancedFlowFilterFileReadResult read_advanced_flow_filter_file_bounded(QFile& file) {
    AdvancedFlowFilterFileReadResult result {};
    result.bytes.reserve(static_cast<qsizetype>(
        std::min<std::size_t>(session_detail::kAdvancedFlowFilterMaxFileBytes + 1U, 64U * 1024U)));

    std::array<char, 4096U> chunk {};
    const auto max_bytes = static_cast<qsizetype>(session_detail::kAdvancedFlowFilterMaxFileBytes);

    while (true) {
        const auto remaining_bytes = static_cast<qint64>(
            session_detail::kAdvancedFlowFilterMaxFileBytes + 1U - static_cast<std::size_t>(result.bytes.size()));
        const auto bytes_to_read = std::min(static_cast<qint64>(chunk.size()), remaining_bytes);
        const auto bytes_read = file.read(chunk.data(), bytes_to_read);
        if (bytes_read < 0) {
            result.status = AdvancedFlowFilterFileReadResult::Status::read_failed;
            result.bytes.clear();
            return result;
        }

        if (bytes_read == 0) {
            if (file.atEnd()) {
                break;
            }
            result.status = AdvancedFlowFilterFileReadResult::Status::read_failed;
            result.bytes.clear();
            return result;
        }

        result.bytes.append(chunk.data(), static_cast<qsizetype>(bytes_read));
        if (result.bytes.size() > max_bytes) {
            result.status = AdvancedFlowFilterFileReadResult::Status::too_large;
            result.bytes.clear();
            return result;
        }

        if (file.atEnd()) {
            break;
        }
    }

    return result;
}

bool protocol_path_layers_have_identifiers(const std::vector<LayerKey>& layers) noexcept {
    return std::any_of(layers.begin(), layers.end(), [](const LayerKey& layer) {
        return layer.identifier.kind != ProtocolLayerIdentifierKind::none;
    });
}

bool protocol_path_layer_matches_predicate(
    const LayerKey& layer,
    const session_detail::AdvancedFlowFilterProtocolLayerPredicate& predicate
) noexcept {
    if (layer.kind != predicate.kind) {
        return false;
    }
    if (!predicate.identifier.has_value()) {
        return true;
    }
    return layer.identifier == *predicate.identifier;
}

bool protocol_path_contains_layer_matches(
    const ProtocolPath& path,
    const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate
) noexcept {
    if (predicate.layers.size() != 1U) {
        return false;
    }

    const auto& layer_predicate = predicate.layers.front();
    return std::any_of(path.layers().begin(), path.layers().end(), [&](const LayerKey& layer) {
        return protocol_path_layer_matches_predicate(layer, layer_predicate);
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

ProtocolPathStatisticsMode protocol_path_selector_mode_for_predicate(
    const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate
) noexcept {
    if (predicate.match_kind == session_detail::AdvancedFlowFilterProtocolPathMatchKind::exact_path) {
        return ProtocolPathStatisticsMode::terminal_paths;
    }

    return protocol_path_layers_have_identifiers(protocol_path_layers_from_predicate(predicate.layers))
        ? ProtocolPathStatisticsMode::identity_tree
        : ProtocolPathStatisticsMode::kind_overview;
}

std::optional<bool> protocol_path_predicate_applicability(
    const CaptureSession& session,
    const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate
) {
    if (!session.has_capture()) {
        return std::nullopt;
    }

    if (predicate.match_kind == session_detail::AdvancedFlowFilterProtocolPathMatchKind::contains_layer) {
        const auto summary = session.protocol_path_summary(ProtocolPathStatisticsMode::terminal_paths);
        return std::any_of(summary.rows.begin(), summary.rows.end(), [&](const auto& row) {
            return protocol_path_contains_layer_matches(row.path, predicate);
        });
    }

    const auto summary = session.protocol_path_summary(protocol_path_selector_mode_for_predicate(predicate));
    const auto predicate_layers = protocol_path_layers_from_predicate(predicate.layers);
    return std::any_of(summary.rows.begin(), summary.rows.end(), [&](const auto& row) {
        return row.path.layers() == predicate_layers;
    });
}

struct OpenJobResult {
    bool opened {false};
    bool cancelled {false};
    bool as_index {false};
    QString input_path {};
    QString error_text {};
    CaptureSession session {};
};

struct AnalysisSequenceExportRow {
    std::uint64_t flow_packet_index {0};
    std::uint64_t packet_index {0};
    std::string direction_text {};
    std::string timestamp_text {};
    std::uint64_t delta_us {0};
    std::uint32_t captured_length {0};
    std::uint32_t original_length {0};
    std::optional<std::uint32_t> transport_payload_length {};
    std::string tcp_flags_text {};
    std::string protocol_hint_text {};
};

struct TransportPayloadLengths {
    std::optional<std::uint32_t> real_payload_length {};
    std::optional<std::uint32_t> original_payload_length {};
    std::optional<bool> is_ip_fragmented {};
};

FlowListModel::SortKey sort_key_from_column(const int column) {
    switch (column) {
    case 0:
        return FlowListModel::SortKey::index;
    case 1:
        return FlowListModel::SortKey::family;
    case 2:
        return FlowListModel::SortKey::protocol;
    case 3:
        return FlowListModel::SortKey::protocol_hint;
    case 4:
        return FlowListModel::SortKey::service_hint;
    case 5:
        return FlowListModel::SortKey::fragmented_packets;
    case 6:
        return FlowListModel::SortKey::address_a;
    case 7:
        return FlowListModel::SortKey::port_a;
    case 8:
        return FlowListModel::SortKey::address_b;
    case 9:
        return FlowListModel::SortKey::port_b;
    case 10:
        return FlowListModel::SortKey::packets;
    case 11:
        return FlowListModel::SortKey::bytes;
    default:
        return FlowListModel::SortKey::index;
    }
}

int column_from_sort_key(const FlowListModel::SortKey key) noexcept {
    switch (key) {
    case FlowListModel::SortKey::index:
        return 0;
    case FlowListModel::SortKey::family:
        return 1;
    case FlowListModel::SortKey::protocol:
        return 2;
    case FlowListModel::SortKey::protocol_hint:
        return 3;
    case FlowListModel::SortKey::service_hint:
        return 4;
    case FlowListModel::SortKey::fragmented_packets:
        return 5;
    case FlowListModel::SortKey::address_a:
        return 6;
    case FlowListModel::SortKey::port_a:
        return 7;
    case FlowListModel::SortKey::address_b:
        return 8;
    case FlowListModel::SortKey::port_b:
        return 9;
    case FlowListModel::SortKey::packets:
        return 10;
    case FlowListModel::SortKey::bytes:
        return 11;
    }

    return 0;
}

QString formatHex16(const std::uint16_t value) {
    return QStringLiteral("0x%1").arg(value, 4, 16, QChar('0'));
}

QString formatProtocol(const std::uint8_t protocol) {
    switch (static_cast<ProtocolId>(protocol)) {
    case ProtocolId::arp:
        return "ARP";
    case ProtocolId::icmp:
        return "ICMP";
    case ProtocolId::igmp:
        return "IGMP";
    case ProtocolId::tcp:
        return "TCP";
    case ProtocolId::udp:
        return "UDP";
    case ProtocolId::esp:
        return "ESP";
    case ProtocolId::sctp:
        return "SCTP";
    case ProtocolId::icmpv6:
        return "ICMPv6";
    default:
        return QStringLiteral("%1").arg(protocol);
    }
}

QString formatCaptureStorageSummaryText(const CaptureStorageSummary& summary) {
    QStringList lines {};
    lines << QStringLiteral("Capture storage summary");
    lines << QStringLiteral("Total packets seen: %1").arg(summary.total_packets_seen);
    lines << QStringLiteral("Recognized packets: %1").arg(summary.recognized_packets);
    lines << QStringLiteral("Unrecognized packets: %1").arg(summary.unrecognized_packets);
    lines << QStringLiteral("IPv4 connections: %1").arg(summary.ipv4_connection_count);
    lines << QStringLiteral("IPv6 connections: %1").arg(summary.ipv6_connection_count);
    lines << QStringLiteral("Flows: %1").arg(summary.flow_count);
    lines << QStringLiteral("Connection packet refs: %1").arg(summary.connection_packet_refs);
    lines << QStringLiteral("Unrecognized packet refs: %1").arg(summary.unrecognized_packet_refs);
    lines << QStringLiteral("Unique protocol paths: %1").arg(summary.unique_protocol_paths);
    lines << QStringLiteral("Protocol path layers total/max: %1 / %2")
        .arg(summary.protocol_path_layers_total)
        .arg(summary.protocol_path_max_depth);
    lines << QStringLiteral("sizeof(PacketRef): %1").arg(summary.sizeof_packet_ref);
    lines << QStringLiteral("sizeof(UnrecognizedPacketRecord): %1").arg(summary.sizeof_unrecognized_packet_record);
    lines << QStringLiteral("sizeof(LayerKey): %1").arg(summary.sizeof_layer_key);
    lines << QStringLiteral("Approx connection PacketRef bytes: %1").arg(summary.approx_connection_packet_ref_bytes);
    lines << QStringLiteral("Approx unrecognized record bytes: %1").arg(summary.approx_unrecognized_record_bytes);
    lines << QStringLiteral("Approx unrecognized reason text bytes: %1").arg(summary.approx_unrecognized_reason_text_bytes);
    lines << QStringLiteral("Approx protocol path layer payload bytes: %1")
        .arg(summary.approx_protocol_path_layer_payload_bytes);
    lines << QStringLiteral("Notes: estimates exclude allocator, hash-node, and transient UI/frontend copy overhead.");
    return lines.join(QLatin1Char('\n'));
}

QVariantList build_protocol_hint_distribution_rows(const CaptureProtocolSummary& summary) {
    const auto shared_rows = session_detail::build_protocol_hint_statistics_rows(summary);
    QVariantList rows {};
    rows.reserve(static_cast<qsizetype>(shared_rows.size()));
    for (const auto& hint_row : shared_rows) {
        QVariantMap row {};
        row.insert(QStringLiteral("title"), QString::fromStdString(hint_row.protocol_label));
        row.insert(QStringLiteral("group"), QString::fromStdString(hint_row.group));
        row.insert(QStringLiteral("flows"), static_cast<qulonglong>(hint_row.flow_count));
        row.insert(QStringLiteral("flowCountText"), QString::fromStdString(hint_row.flow_count_text));
        row.insert(QStringLiteral("packets"), static_cast<qulonglong>(hint_row.packet_count));
        row.insert(QStringLiteral("packetCountText"), QString::fromStdString(hint_row.packet_count_text));
        row.insert(QStringLiteral("capturedBytes"), static_cast<qulonglong>(hint_row.captured_bytes));
        row.insert(QStringLiteral("capturedBytesText"), QString::fromStdString(hint_row.captured_bytes_text));
        row.insert(QStringLiteral("originalBytes"), static_cast<qulonglong>(hint_row.original_bytes));
        row.insert(QStringLiteral("originalBytesText"), QString::fromStdString(hint_row.original_bytes_text));
        row.insert(QStringLiteral("bytes"), static_cast<qulonglong>(hint_row.original_bytes));
        rows.push_back(row);
    }
    return rows;
}

QString format_size_value(const std::uint64_t value);

QVariantList build_packet_size_distribution_rows(const CapturePacketSizeStatistics& statistics) {
    QVariantList rows {};
    rows.reserve(static_cast<qsizetype>(statistics.buckets.size()));

    for (const auto& bucket : statistics.buckets) {
        QVariantMap row {};
        row.insert(
            QStringLiteral("bucketId"),
            QString::fromUtf8(bucket.stable_id.data(), static_cast<qsizetype>(bucket.stable_id.size()))
        );
        row.insert(QStringLiteral("label"), QString::fromStdString(session_detail::capture_packet_size_bucket_label(bucket)));
        row.insert(QStringLiteral("lowerBoundInclusive"), static_cast<qulonglong>(bucket.lower_bound_inclusive));
        row.insert(QStringLiteral("upperBoundInclusive"), bucket.upper_bound_inclusive.has_value()
            ? QVariant::fromValue<qulonglong>(static_cast<qulonglong>(*bucket.upper_bound_inclusive))
            : QVariant {});
        row.insert(QStringLiteral("packetCount"), static_cast<qulonglong>(bucket.packet_count));
        row.insert(QStringLiteral("normalizedFraction"),
            statistics.maximum_bucket_packet_count > 0U
                ? static_cast<double>(bucket.packet_count) / static_cast<double>(statistics.maximum_bucket_packet_count)
                : 0.0);
        rows.push_back(row);
    }

    return rows;
}

QVariantList build_flow_packet_histogram_rows(const FlowPacketCountHistogram& histogram) {
    QVariantList rows {};
    rows.reserve(static_cast<qsizetype>(histogram.buckets.size()));

    const auto max_flow_count = histogram.maximum_bucket_flow_count;
    const auto max_original_byte_count = histogram.maximum_bucket_original_byte_count;
    for (const auto& bucket : histogram.buckets) {
        QVariantMap row {};
        row.insert(QStringLiteral("bucketId"), QString::fromStdString(bucket.stable_id));
        row.insert(QStringLiteral("lowerBoundInclusive"), static_cast<qulonglong>(bucket.lower_bound_inclusive));
        row.insert(QStringLiteral("upperBoundInclusive"), bucket.upper_bound_inclusive.has_value()
            ? QVariant::fromValue<qulonglong>(static_cast<qulonglong>(*bucket.upper_bound_inclusive))
            : QVariant {});
        row.insert(QStringLiteral("label"), bucket.upper_bound_inclusive.has_value()
            ? (*bucket.upper_bound_inclusive == bucket.lower_bound_inclusive
                ? QString::number(bucket.lower_bound_inclusive)
                : QStringLiteral("%1-%2").arg(bucket.lower_bound_inclusive).arg(*bucket.upper_bound_inclusive))
            : QStringLiteral("%1+").arg(bucket.lower_bound_inclusive));
        row.insert(QStringLiteral("flowCount"), static_cast<qulonglong>(bucket.flow_count));
        row.insert(QStringLiteral("originalByteCount"), static_cast<qulonglong>(bucket.original_byte_count));
        row.insert(QStringLiteral("originalByteCountText"), format_size_value(bucket.original_byte_count));
        const auto normalized_flow_fraction =
            max_flow_count > 0U
                ? static_cast<double>(bucket.flow_count) / static_cast<double>(max_flow_count)
                : 0.0;
        row.insert(QStringLiteral("normalizedFraction"), normalized_flow_fraction);
        row.insert(QStringLiteral("normalizedFlowFraction"), normalized_flow_fraction);
        row.insert(QStringLiteral("normalizedOriginalByteFraction"),
            max_original_byte_count > 0U
                ? static_cast<double>(bucket.original_byte_count) / static_cast<double>(max_original_byte_count)
                : 0.0);
        rows.push_back(row);
    }

    return rows;
}

QString selected_flow_service_hint(const FlowListModel& flow_model, const int selected_flow_index) {
    if (selected_flow_index < 0) {
        return {};
    }

    const auto row = flow_model.rowForFlowIndex(selected_flow_index);
    if (row < 0) {
        return {};
    }

    return flow_model.data(flow_model.index(row, 0), FlowListModel::ServiceHintRole).toString();
}

QString selected_flow_protocol_hint(const FlowListModel& flow_model, const int selected_flow_index) {
    if (selected_flow_index < 0) {
        return {};
    }

    const auto row = flow_model.rowForFlowIndex(selected_flow_index);
    if (row < 0) {
        return {};
    }

    return flow_model.data(flow_model.index(row, 0), FlowListModel::ProtocolHintRole).toString();
}

bool selected_flow_uses_tcp(const FlowListModel& flow_model, const int selected_flow_index) {
    if (selected_flow_index < 0) {
        return false;
    }

    const auto row = flow_model.rowForFlowIndex(selected_flow_index);
    if (row < 0) {
        return false;
    }

    return flow_model.data(flow_model.index(row, 0), FlowListModel::ProtocolRole)
        .toString()
        .compare(QStringLiteral("TCP"), Qt::CaseInsensitive) == 0;
}

QString selected_flow_wireshark_filter(const FlowListModel& flow_model, const int selected_flow_index) {
    if (selected_flow_index < 0) {
        return {};
    }

    const auto row = flow_model.rowForFlowIndex(selected_flow_index);
    if (row < 0) {
        return {};
    }

    const auto model_index = flow_model.index(row, 0);
    const auto family = flow_model.data(model_index, FlowListModel::FamilyRole).toString();
    const auto protocol = flow_model.data(model_index, FlowListModel::ProtocolRole).toString();
    const auto address_a = flow_model.data(model_index, FlowListModel::AddressARole).toString();
    const auto address_b = flow_model.data(model_index, FlowListModel::AddressBRole).toString();
    const auto port_a = flow_model.data(model_index, FlowListModel::PortARole).toUInt();
    const auto port_b = flow_model.data(model_index, FlowListModel::PortBRole).toUInt();

    const QString address_term = family.compare(QStringLiteral("IPv6"), Qt::CaseInsensitive) == 0
        ? QStringLiteral("ipv6.addr")
        : (family.compare(QStringLiteral("IPv4"), Qt::CaseInsensitive) == 0 ? QStringLiteral("ip.addr") : QString {});

    const QString port_term = protocol.compare(QStringLiteral("TCP"), Qt::CaseInsensitive) == 0
        ? QStringLiteral("tcp.port")
        : (protocol.compare(QStringLiteral("UDP"), Qt::CaseInsensitive) == 0
            ? QStringLiteral("udp.port")
            : (protocol.compare(QStringLiteral("SCTP"), Qt::CaseInsensitive) == 0
                ? QStringLiteral("sctp.port")
                : QString {}));

    if (address_term.isEmpty() || port_term.isEmpty() || address_a.isEmpty() || address_b.isEmpty()) {
        return {};
    }

    const auto selected_port = std::max(port_a, port_b);
    return QStringLiteral("%1 == %2 && %1 == %3 && %4 == %5")
        .arg(address_term, address_a, address_b, port_term, QString::number(selected_port));
}

QString format_protocol_hint_display(const QString& protocol_hint) {
    if (protocol_hint.compare(QStringLiteral("possible_tls"), Qt::CaseInsensitive) == 0) {
        return QStringLiteral("Possible TLS");
    }
    if (protocol_hint.compare(QStringLiteral("possible_quic"), Qt::CaseInsensitive) == 0) {
        return QStringLiteral("Possible QUIC");
    }
    if (protocol_hint.compare(QStringLiteral("igmp"), Qt::CaseInsensitive) == 0) {
        return QStringLiteral("IGMP");
    }
    if (protocol_hint.compare(QStringLiteral("igmpv1"), Qt::CaseInsensitive) == 0) {
        return QStringLiteral("IGMPv1");
    }
    if (protocol_hint.compare(QStringLiteral("igmpv2"), Qt::CaseInsensitive) == 0) {
        return QStringLiteral("IGMPv2");
    }
    if (protocol_hint.compare(QStringLiteral("igmpv3"), Qt::CaseInsensitive) == 0) {
        return QStringLiteral("IGMPv3");
    }
    if (protocol_hint.compare(QStringLiteral("mdns"), Qt::CaseInsensitive) == 0) {
        return QStringLiteral("mDNS");
    }

    return protocol_hint.toUpper();
}

QString selected_flow_endpoint_summary(const FlowListModel& flow_model, const int selected_flow_index) {
    if (selected_flow_index < 0) {
        return {};
    }

    const auto row = flow_model.rowForFlowIndex(selected_flow_index);
    if (row < 0) {
        return {};
    }

    const auto index = flow_model.index(row, 0);
    const auto address_a = flow_model.data(index, FlowListModel::AddressARole).toString();
    const auto port_a = flow_model.data(index, FlowListModel::PortARole).toInt();
    const auto address_b = flow_model.data(index, FlowListModel::AddressBRole).toString();
    const auto port_b = flow_model.data(index, FlowListModel::PortBRole).toInt();
    const auto protocol = flow_model.data(index, FlowListModel::ProtocolRole).toString();
    return QStringLiteral("%1:%2 \u2192 %3:%4 %5")
        .arg(address_a)
        .arg(port_a)
        .arg(address_b)
        .arg(port_b)
        .arg(protocol);
}

std::uint64_t packet_timestamp_us(const PacketRef& packet) noexcept {
    return (static_cast<std::uint64_t>(packet.ts_sec) * 1000000ULL) + static_cast<std::uint64_t>(packet.ts_usec);
}

std::string normalize_sequence_direction(const std::string& direction_text) {
    if (direction_text == "A\xE2\x86\x92" "B") {
        return "A->B";
    }
    if (direction_text == "B\xE2\x86\x92" "A") {
        return "B->A";
    }

    return direction_text;
}

std::string escape_csv_field(const std::string& field) {
    if (field.find_first_of(",\"\r\n") == std::string::npos) {
        return field;
    }

    std::string escaped {};
    escaped.reserve(field.size() + 2U);
    escaped.push_back('"');
    for (const auto ch : field) {
        if (ch == '"') {
            escaped.push_back('"');
        }
        escaped.push_back(ch);
    }
    escaped.push_back('"');
    return escaped;
}

QString from_latin1_view(const std::string_view value) {
    return QString::fromLatin1(value.data(), static_cast<qsizetype>(value.size()));
}

std::optional<std::uint64_t> parse_positive_u64(const QString& text) {
    bool ok = false;
    const auto value = text.trimmed().toULongLong(&ok);
    if (!ok || value == 0U) {
        return std::nullopt;
    }

    return static_cast<std::uint64_t>(value);
}

TransportPayloadLengths resolve_transport_payload_lengths(
    const PacketDetails& details,
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet
) {
    const auto metadata = session_detail::derive_transient_packet_metadata(packet_bytes, packet);

    if (!details.has_tcp && !details.has_udp) {
        return TransportPayloadLengths {
            .is_ip_fragmented = metadata.is_ip_fragmented,
        };
    }

    return TransportPayloadLengths {
        .real_payload_length = metadata.captured_transport_payload_length,
        .original_payload_length = metadata.original_transport_payload_length,
        .is_ip_fragmented = metadata.is_ip_fragmented,
    };
}

void apply_transient_packet_row_metadata(
    CaptureSession& session,
    const std::size_t flow_index,
    std::vector<PacketRow>& rows
) {
    session_detail::populate_transient_packet_row_metadata(session, flow_index, rows);
}

std::optional<std::vector<AnalysisSequenceExportRow>> build_analysis_sequence_export_rows(
    const CaptureSession& session,
    const std::size_t flow_index,
    const QString& protocol_hint
) {
    const auto packet_rows = session.list_flow_packets(flow_index);
    const auto packets = session.flow_packets(flow_index);
    if (!packets.has_value() || packet_rows.size() != packets->size()) {
        return std::nullopt;
    }

    std::vector<AnalysisSequenceExportRow> rows {};
    rows.reserve(packet_rows.size());

    const auto protocol_hint_text = protocol_hint.toStdString();
    std::optional<std::uint64_t> previous_timestamp_us {};
    for (std::size_t index = 0; index < packet_rows.size(); ++index) {
        const auto& packet_row = packet_rows[index];
        const auto& packet = packets->at(index);
        if (packet_row.packet_index != packet.packet_index) {
            return std::nullopt;
        }

        const auto metadata = session_detail::derive_transient_packet_metadata(session, packet);
        const auto timestamp_us = packet_timestamp_us(packet);
        const auto delta_us = previous_timestamp_us.has_value() && timestamp_us >= *previous_timestamp_us
            ? timestamp_us - *previous_timestamp_us
            : 0U;

        rows.push_back(AnalysisSequenceExportRow {
            .flow_packet_index = packet_row.row_number,
            .packet_index = packet.packet_index,
            .direction_text = normalize_sequence_direction(packet_row.direction_text),
            .timestamp_text = packet_row.timestamp_text,
            .delta_us = delta_us,
            .captured_length = packet.captured_length,
            .original_length = packet.original_length,
            .transport_payload_length = metadata.original_transport_payload_length,
            .tcp_flags_text = metadata.tcp_flags.has_value()
                ? session_detail::format_tcp_flags_text(*metadata.tcp_flags)
                : packet_row.tcp_flags_text,
            .protocol_hint_text = protocol_hint_text,
        });

        previous_timestamp_us = timestamp_us;
    }

    return rows;
}

bool write_analysis_sequence_csv(const std::vector<AnalysisSequenceExportRow>& rows, const std::filesystem::path& output_path, QString* error_text) {
    std::ofstream stream {output_path, std::ios::binary | std::ios::trunc};
    if (!stream.is_open()) {
        if (error_text != nullptr) {
            *error_text = QStringLiteral("Failed to open output CSV file.");
        }
        return false;
    }

    stream << "flow_packet_index,packet_index,direction,timestamp,delta_us,captured_length,original_length,transport_payload_length,tcp_flags,protocol_hint\n";
    for (const auto& row : rows) {
        stream << row.flow_packet_index << ','
               << row.packet_index << ','
               << escape_csv_field(row.direction_text) << ','
               << escape_csv_field(row.timestamp_text) << ','
               << row.delta_us << ','
               << row.captured_length << ','
               << row.original_length << ','
               << (row.transport_payload_length.has_value() ? std::to_string(*row.transport_payload_length) : std::string {}) << ','
               << escape_csv_field(row.tcp_flags_text) << ','
               << escape_csv_field(row.protocol_hint_text) << '\n';
    }

    if (!stream.good()) {
        if (error_text != nullptr) {
            *error_text = QStringLiteral("Failed to write flow sequence CSV.");
        }
        return false;
    }

    return true;
}

QString formatIpv4Address(const std::uint32_t address) {
    return QStringLiteral("%1.%2.%3.%4")
        .arg((address >> 24U) & 0xFFU)
        .arg((address >> 16U) & 0xFFU)
        .arg((address >> 8U) & 0xFFU)
        .arg(address & 0xFFU);
}

QString formatIpv6Address(const std::array<std::uint8_t, 16>& address) {
    QStringList parts {};
    parts.reserve(8);

    for (std::size_t index = 0; index < 8; ++index) {
        const auto word = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(address[index * 2U]) << 8U) |
            static_cast<std::uint16_t>(address[index * 2U + 1U])
        );
        parts.push_back(QStringLiteral("%1").arg(word, 4, 16, QChar('0')));
    }

    return parts.join(QStringLiteral(":"));
}

QString formatTcpFlags(const std::uint8_t flags) {
    struct FlagName {
        std::uint8_t mask;
        const char* name;
    };

    constexpr FlagName names[] {
        {0x80U, "CWR"},
        {0x40U, "ECE"},
        {0x20U, "URG"},
        {0x10U, "ACK"},
        {0x08U, "PSH"},
        {0x04U, "RST"},
        {0x02U, "SYN"},
        {0x01U, "FIN"},
    };

    QStringList parts {};
    for (const auto& flag : names) {
        if ((flags & flag.mask) != 0U) {
            parts.push_back(QString::fromLatin1(flag.name));
        }
    }

    return parts.isEmpty() ? QStringLiteral("none") : parts.join(QStringLiteral("|"));
}

void appendSection(QStringList& lines, const QString& title, const QStringList& values) {
    if (values.isEmpty()) {
        return;
    }

    if (!lines.isEmpty()) {
        lines.push_back({});
    }

    lines.push_back(title);
    for (const auto& value : values) {
        lines.push_back(QStringLiteral("  %1").arg(value));
    }
}

ProtocolPathStatisticsMode protocol_path_statistics_mode_from_int(const int mode) noexcept {
    switch (mode) {
    case kProtocolPathStatisticsModeIdentityTree:
        return ProtocolPathStatisticsMode::identity_tree;
    case kProtocolPathStatisticsModeTerminalPaths:
        return ProtocolPathStatisticsMode::terminal_paths;
    case kProtocolPathStatisticsModeKindOverview:
    default:
        return ProtocolPathStatisticsMode::kind_overview;
    }
}

QString protocol_path_statistics_mode_label(const ProtocolPathStatisticsMode mode) {
    switch (mode) {
    case ProtocolPathStatisticsMode::identity_tree:
        return QStringLiteral("Identity tree");
    case ProtocolPathStatisticsMode::terminal_paths:
        return QStringLiteral("Terminal paths");
    case ProtocolPathStatisticsMode::kind_overview:
    default:
        return QStringLiteral("Kind overview");
    }
}

QVariantList protocol_path_legend_to_variant_list() {
    QVariantList legend {};
    const auto entries = session_detail::protocol_path_legend_entries();
    legend.reserve(static_cast<qsizetype>(entries.size()));

    for (const auto& entry : entries) {
        QVariantMap row {};
        row.insert(QStringLiteral("shortLabel"), QString::fromStdString(entry.short_label));
        row.insert(QStringLiteral("fullName"), QString::fromStdString(entry.full_name));
        row.insert(QStringLiteral("colorKey"), QString::fromStdString(entry.color_key));
        row.insert(QStringLiteral("backgroundColor"), QString::fromStdString(entry.background_color));
        row.insert(QStringLiteral("borderColor"), QString::fromStdString(entry.border_color));
        row.insert(QStringLiteral("textColor"), QString::fromStdString(entry.text_color));
        legend.push_back(row);
    }

    return legend;
}

QVariantList supported_protocol_catalog_to_variant_list() {
    QVariantList catalog {};
    const auto rows = session_detail::supported_protocol_catalog_rows();
    catalog.reserve(static_cast<qsizetype>(rows.size()));

    for (const auto& row : rows) {
        QVariantMap item {};
        item.insert(QStringLiteral("categoryId"), from_latin1_view(session_detail::supported_protocol_category_stable_id(row.category)));
        item.insert(QStringLiteral("categoryLabel"), from_latin1_view(session_detail::supported_protocol_category_display_label(row.category)));
        item.insert(QStringLiteral("protocolId"), from_latin1_view(row.stable_id));
        item.insert(QStringLiteral("protocol"), from_latin1_view(row.protocol));
        item.insert(QStringLiteral("recognitionStatusId"), from_latin1_view(session_detail::supported_protocol_status_stable_id(row.recognition)));
        item.insert(QStringLiteral("recognitionStatusLabel"), from_latin1_view(session_detail::supported_protocol_status_display_label(row.recognition)));
        item.insert(QStringLiteral("serviceStatusId"), from_latin1_view(session_detail::supported_protocol_status_stable_id(row.service)));
        item.insert(QStringLiteral("serviceStatusLabel"), from_latin1_view(session_detail::supported_protocol_status_display_label(row.service)));
        item.insert(QStringLiteral("packetSummaryStatusId"), from_latin1_view(session_detail::supported_protocol_status_stable_id(row.packet_summary)));
        item.insert(QStringLiteral("packetSummaryStatusLabel"), from_latin1_view(session_detail::supported_protocol_status_display_label(row.packet_summary)));
        item.insert(QStringLiteral("streamStatusId"), from_latin1_view(session_detail::supported_protocol_status_stable_id(row.stream)));
        item.insert(QStringLiteral("streamStatusLabel"), from_latin1_view(session_detail::supported_protocol_status_display_label(row.stream)));
        item.insert(QStringLiteral("notes"), from_latin1_view(row.notes));
        catalog.push_back(item);
    }

    return catalog;
}

enum class ChecksumValidationStatus {
    valid,
    invalid,
    unavailable,
    not_checked,
};

struct ChecksumValidationResult {
    ChecksumValidationStatus status {ChecksumValidationStatus::unavailable};
    QString note {};
};

struct PacketChecksumSections {
    QStringList summary_lines {};
    QStringList warnings {};
};

QString checksum_status_text(const ChecksumValidationStatus status) {
    switch (status) {
    case ChecksumValidationStatus::valid:
        return QStringLiteral("valid");
    case ChecksumValidationStatus::invalid:
        return QStringLiteral("invalid");
    case ChecksumValidationStatus::unavailable:
        return QStringLiteral("unavailable");
    case ChecksumValidationStatus::not_checked:
        return QStringLiteral("not checked");
    }

    return QStringLiteral("unavailable");
}

void append_be16_bytes(std::vector<std::uint8_t>& bytes, const std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

void append_be32_bytes(std::vector<std::uint8_t>& bytes, const std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

std::uint16_t compute_internet_checksum(std::span<const std::uint8_t> bytes) {
    std::uint32_t sum = 0U;
    std::size_t index = 0U;
    while (index + 1U < bytes.size()) {
        sum += static_cast<std::uint32_t>(
            (static_cast<std::uint16_t>(bytes[index]) << 8U) |
            static_cast<std::uint16_t>(bytes[index + 1U])
        );
        index += 2U;
    }

    if (index < bytes.size()) {
        sum += static_cast<std::uint32_t>(static_cast<std::uint16_t>(bytes[index]) << 8U);
    }

    while ((sum >> 16U) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }

    return static_cast<std::uint16_t>(~sum & 0xFFFFU);
}

std::vector<std::uint8_t> copy_zeroed_range(
    std::span<const std::uint8_t> bytes,
    const std::size_t offset,
    const std::size_t length,
    const std::size_t zero_offset,
    const std::size_t zero_length
) {
    std::vector<std::uint8_t> copied(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                                     bytes.begin() + static_cast<std::ptrdiff_t>(offset + length));
    if (zero_offset >= offset && zero_offset + zero_length <= offset + length) {
        const auto local_offset = zero_offset - offset;
        for (std::size_t index = 0; index < zero_length; ++index) {
            copied[local_offset + index] = 0U;
        }
    }
    return copied;
}

ChecksumValidationResult validate_ipv4_header_checksum(
    std::span<const std::uint8_t> packet_bytes,
    const PacketDetails& details,
    const PacketRef& packet
) {
    const auto network = detail::parse_network_payload(packet_bytes, packet.data_link_type);
    if (!network.has_value() || network->protocol_type != detail::kEtherTypeIpv4) {
        return {};
    }

    const auto ipv4_bounds = detail::parse_ipv4_packet_bounds(packet_bytes, network->payload_offset);
    if (!ipv4_bounds.has_value()) {
        return {};
    }

    const auto checksum_offset = network->payload_offset + 10U;
    if (checksum_offset + 2U > packet_bytes.size()) {
        return {};
    }

    const auto stored_checksum = detail::read_be16(packet_bytes, checksum_offset);
    const auto header_bytes = copy_zeroed_range(
        packet_bytes,
        network->payload_offset,
        ipv4_bounds->header_length,
        checksum_offset,
        2U
    );
    const auto computed_checksum = compute_internet_checksum(header_bytes);
    if (computed_checksum == stored_checksum) {
        return ChecksumValidationResult {
            .status = ChecksumValidationStatus::valid,
        };
    }

    if (details.ipv4_bounds_from_captured_bytes) {
        return ChecksumValidationResult {
            .status = ChecksumValidationStatus::unavailable,
            .note = QStringLiteral("Possible pre-offload packet; IPv4 checksum may be incomplete or not finalized."),
        };
    }

    return ChecksumValidationResult {
        .status = ChecksumValidationStatus::invalid,
    };
}

ChecksumValidationResult validate_tcp_checksum(
    std::span<const std::uint8_t> packet_bytes,
    const PacketDetails& details,
    const PacketRef& packet
) {
    if (session_detail::derive_ip_fragmentation_state_from_packet_details(packet_bytes, packet, details).value_or(false)) {
        return ChecksumValidationResult {
            .status = ChecksumValidationStatus::unavailable,
            .note = QStringLiteral("TCP checksum not validated for IP-fragmented packet."),
        };
    }

    if (details.has_ipv4) {
        const auto network = detail::parse_network_payload(packet_bytes, packet.data_link_type);
        if (!network.has_value() || network->protocol_type != detail::kEtherTypeIpv4) {
            return {};
        }

        const auto ipv4_offset = network->payload_offset;
        const auto ipv4_bounds = detail::parse_ipv4_packet_bounds(packet_bytes, ipv4_offset);
        if (!ipv4_bounds.has_value()) {
            return {};
        }

        if (details.ipv4_bounds_from_captured_bytes) {
            return ChecksumValidationResult {
                .status = ChecksumValidationStatus::unavailable,
                .note = QStringLiteral("Possible pre-offload packet; TCP checksum may be incomplete or not finalized."),
            };
        }

        if (packet.captured_length < packet.original_length || packet_bytes.size() < ipv4_bounds->nominal_packet_end) {
            return ChecksumValidationResult {
                .status = ChecksumValidationStatus::unavailable,
                .note = QStringLiteral("Packet is truncated in capture; full TCP segment bytes are unavailable."),
            };
        }

        const auto transport_offset = ipv4_offset + ipv4_bounds->header_length;
        if (transport_offset + detail::kTcpMinimumHeaderSize > packet_bytes.size()) {
            return {};
        }

        const auto tcp_header_length = static_cast<std::size_t>((packet_bytes[transport_offset + 12U] >> 4U) * 4U);
        const auto segment_length = static_cast<std::size_t>(ipv4_bounds->total_length) - ipv4_bounds->header_length;
        if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
            transport_offset + segment_length > packet_bytes.size() ||
            segment_length < tcp_header_length) {
            return {};
        }

        const auto checksum_offset = transport_offset + 16U;
        const auto stored_checksum = detail::read_be16(packet_bytes, checksum_offset);

        std::vector<std::uint8_t> checksum_bytes {};
        checksum_bytes.reserve(12U + segment_length + (segment_length % 2U));
        append_be32_bytes(checksum_bytes, details.ipv4.src_addr);
        append_be32_bytes(checksum_bytes, details.ipv4.dst_addr);
        checksum_bytes.push_back(0U);
        checksum_bytes.push_back(detail::kIpProtocolTcp);
        append_be16_bytes(checksum_bytes, static_cast<std::uint16_t>(segment_length));
        const auto segment_bytes = copy_zeroed_range(packet_bytes, transport_offset, segment_length, checksum_offset, 2U);
        checksum_bytes.insert(checksum_bytes.end(), segment_bytes.begin(), segment_bytes.end());

        return ChecksumValidationResult {
            .status = compute_internet_checksum(checksum_bytes) == stored_checksum
                ? ChecksumValidationStatus::valid
                : ChecksumValidationStatus::invalid,
        };
    }

    if (details.has_ipv6) {
        const auto network = detail::parse_network_payload(packet_bytes, packet.data_link_type);
        if (!network.has_value() || network->protocol_type != detail::kEtherTypeIpv6) {
            return {};
        }

        const auto ipv6_offset = network->payload_offset;
        const auto payload = detail::parse_ipv6_payload(packet_bytes, ipv6_offset);
        if (!payload.has_value() || payload->has_fragment_header) {
            return ChecksumValidationResult {
                .status = ChecksumValidationStatus::unavailable,
                .note = QStringLiteral("TCP checksum not validated for fragmented IPv6 packet."),
            };
        }

        const auto ipv6_payload_length = static_cast<std::size_t>(detail::read_be16(packet_bytes, ipv6_offset + 4U));
        const auto nominal_packet_end = ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length;
        if (packet.captured_length < packet.original_length || packet_bytes.size() < nominal_packet_end) {
            return ChecksumValidationResult {
                .status = ChecksumValidationStatus::unavailable,
                .note = QStringLiteral("Packet is truncated in capture; full TCP segment bytes are unavailable."),
            };
        }

        const auto transport_offset = payload->payload_offset;
        if (transport_offset + detail::kTcpMinimumHeaderSize > packet_bytes.size()) {
            return {};
        }

        const auto tcp_header_length = static_cast<std::size_t>((packet_bytes[transport_offset + 12U] >> 4U) * 4U);
        const auto segment_length = nominal_packet_end - transport_offset;
        if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
            transport_offset + segment_length > packet_bytes.size() ||
            segment_length < tcp_header_length) {
            return {};
        }

        const auto checksum_offset = transport_offset + 16U;
        const auto stored_checksum = detail::read_be16(packet_bytes, checksum_offset);

        std::vector<std::uint8_t> checksum_bytes {};
        checksum_bytes.reserve(40U + segment_length + (segment_length % 2U));
        checksum_bytes.insert(checksum_bytes.end(), details.ipv6.src_addr.begin(), details.ipv6.src_addr.end());
        checksum_bytes.insert(checksum_bytes.end(), details.ipv6.dst_addr.begin(), details.ipv6.dst_addr.end());
        append_be32_bytes(checksum_bytes, static_cast<std::uint32_t>(segment_length));
        checksum_bytes.push_back(0U);
        checksum_bytes.push_back(0U);
        checksum_bytes.push_back(0U);
        checksum_bytes.push_back(detail::kIpProtocolTcp);
        const auto segment_bytes = copy_zeroed_range(packet_bytes, transport_offset, segment_length, checksum_offset, 2U);
        checksum_bytes.insert(checksum_bytes.end(), segment_bytes.begin(), segment_bytes.end());

        return ChecksumValidationResult {
            .status = compute_internet_checksum(checksum_bytes) == stored_checksum
                ? ChecksumValidationStatus::valid
                : ChecksumValidationStatus::invalid,
        };
    }

    return {};
}

ChecksumValidationResult validate_udp_checksum(
    std::span<const std::uint8_t> packet_bytes,
    const PacketDetails& details,
    const PacketRef& packet
) {
    if (session_detail::derive_ip_fragmentation_state_from_packet_details(packet_bytes, packet, details).value_or(false)) {
        return ChecksumValidationResult {
            .status = ChecksumValidationStatus::unavailable,
            .note = QStringLiteral("UDP checksum not validated for IP-fragmented packet."),
        };
    }

    if (details.has_ipv4) {
        const auto network = detail::parse_network_payload(packet_bytes, packet.data_link_type);
        if (!network.has_value() || network->protocol_type != detail::kEtherTypeIpv4) {
            return {};
        }

        const auto ipv4_offset = network->payload_offset;
        const auto ipv4_bounds = detail::parse_ipv4_packet_bounds(packet_bytes, ipv4_offset);
        if (!ipv4_bounds.has_value()) {
            return {};
        }

        if (details.ipv4_bounds_from_captured_bytes) {
            return ChecksumValidationResult {
                .status = ChecksumValidationStatus::unavailable,
                .note = QStringLiteral("Possible pre-offload packet; UDP checksum may be incomplete or not finalized."),
            };
        }

        const auto transport_offset = ipv4_offset + ipv4_bounds->header_length;
        if (transport_offset + detail::kUdpHeaderSize > packet_bytes.size()) {
            return {};
        }

        const auto datagram_length = static_cast<std::size_t>(detail::read_be16(packet_bytes, transport_offset + 4U));
        if (datagram_length < detail::kUdpHeaderSize ||
            transport_offset + datagram_length > ipv4_bounds->nominal_packet_end) {
            return {};
        }

        const auto stored_checksum = detail::read_be16(packet_bytes, transport_offset + 6U);
        if (stored_checksum == 0U) {
            return ChecksumValidationResult {
                .status = ChecksumValidationStatus::not_checked,
                .note = QStringLiteral("UDP checksum is not present in this IPv4 packet."),
            };
        }

        if (packet.captured_length < packet.original_length || packet_bytes.size() < transport_offset + datagram_length) {
            return ChecksumValidationResult {
                .status = ChecksumValidationStatus::unavailable,
                .note = QStringLiteral("Packet is truncated in capture; full UDP datagram bytes are unavailable."),
            };
        }

        std::vector<std::uint8_t> checksum_bytes {};
        checksum_bytes.reserve(12U + datagram_length + (datagram_length % 2U));
        append_be32_bytes(checksum_bytes, details.ipv4.src_addr);
        append_be32_bytes(checksum_bytes, details.ipv4.dst_addr);
        checksum_bytes.push_back(0U);
        checksum_bytes.push_back(detail::kIpProtocolUdp);
        append_be16_bytes(checksum_bytes, static_cast<std::uint16_t>(datagram_length));
        const auto datagram_bytes = copy_zeroed_range(packet_bytes, transport_offset, datagram_length, transport_offset + 6U, 2U);
        checksum_bytes.insert(checksum_bytes.end(), datagram_bytes.begin(), datagram_bytes.end());

        return ChecksumValidationResult {
            .status = compute_internet_checksum(checksum_bytes) == stored_checksum
                ? ChecksumValidationStatus::valid
                : ChecksumValidationStatus::invalid,
        };
    }

    if (details.has_ipv6) {
        const auto network = detail::parse_network_payload(packet_bytes, packet.data_link_type);
        if (!network.has_value() || network->protocol_type != detail::kEtherTypeIpv6) {
            return {};
        }

        const auto ipv6_offset = network->payload_offset;
        const auto payload = detail::parse_ipv6_payload(packet_bytes, ipv6_offset);
        if (!payload.has_value() || payload->has_fragment_header) {
            return ChecksumValidationResult {
                .status = ChecksumValidationStatus::unavailable,
                .note = QStringLiteral("UDP checksum not validated for fragmented IPv6 packet."),
            };
        }

        const auto transport_offset = payload->payload_offset;
        if (transport_offset + detail::kUdpHeaderSize > packet_bytes.size()) {
            return {};
        }

        const auto datagram_length = static_cast<std::size_t>(detail::read_be16(packet_bytes, transport_offset + 4U));
        const auto nominal_packet_end = ipv6_offset + detail::kIpv6HeaderSize + static_cast<std::size_t>(details.ipv6.payload_length);
        if (datagram_length < detail::kUdpHeaderSize || transport_offset + datagram_length > nominal_packet_end) {
            return {};
        }

        const auto stored_checksum = detail::read_be16(packet_bytes, transport_offset + 6U);
        if (stored_checksum == 0U) {
            return ChecksumValidationResult {
                .status = ChecksumValidationStatus::invalid,
                .note = QStringLiteral("UDP checksum is required for IPv6 packets."),
            };
        }

        if (packet.captured_length < packet.original_length || packet_bytes.size() < transport_offset + datagram_length) {
            return ChecksumValidationResult {
                .status = ChecksumValidationStatus::unavailable,
                .note = QStringLiteral("Packet is truncated in capture; full UDP datagram bytes are unavailable."),
            };
        }

        std::vector<std::uint8_t> checksum_bytes {};
        checksum_bytes.reserve(40U + datagram_length + (datagram_length % 2U));
        checksum_bytes.insert(checksum_bytes.end(), details.ipv6.src_addr.begin(), details.ipv6.src_addr.end());
        checksum_bytes.insert(checksum_bytes.end(), details.ipv6.dst_addr.begin(), details.ipv6.dst_addr.end());
        append_be32_bytes(checksum_bytes, static_cast<std::uint32_t>(datagram_length));
        checksum_bytes.push_back(0U);
        checksum_bytes.push_back(0U);
        checksum_bytes.push_back(0U);
        checksum_bytes.push_back(detail::kIpProtocolUdp);
        const auto datagram_bytes = copy_zeroed_range(packet_bytes, transport_offset, datagram_length, transport_offset + 6U, 2U);
        checksum_bytes.insert(checksum_bytes.end(), datagram_bytes.begin(), datagram_bytes.end());

        return ChecksumValidationResult {
            .status = compute_internet_checksum(checksum_bytes) == stored_checksum
                ? ChecksumValidationStatus::valid
                : ChecksumValidationStatus::invalid,
        };
    }

    return {};
}

void append_checksum_line(QStringList& lines, const QString& label, const ChecksumValidationResult& result) {
    lines.push_back(QStringLiteral("%1: %2").arg(label, checksum_status_text(result.status)));
    if (!result.note.isEmpty()) {
        lines.push_back(QStringLiteral("%1 note: %2").arg(label, result.note));
    }
}

bool should_promote_checksum_note_to_warning(const ChecksumValidationResult& result) noexcept {
    return !result.note.isEmpty() &&
        result.status != ChecksumValidationStatus::valid &&
        result.status != ChecksumValidationStatus::not_checked;
}

QString checksum_warning_text(const QString& label, const ChecksumValidationResult& result) {
    if (result.status == ChecksumValidationStatus::invalid) {
        return result.note.isEmpty()
            ? QStringLiteral("%1 is invalid.").arg(label)
            : QStringLiteral("%1 is invalid. %2").arg(label, result.note);
    }

    if (should_promote_checksum_note_to_warning(result)) {
        return result.note;
    }

    return {};
}

PacketChecksumSections build_packet_checksum_sections(
    const PacketDetails& details,
    const PacketRef& packet,
    std::span<const std::uint8_t> packet_bytes
) {
    PacketChecksumSections sections {};

    if (details.has_ipv4) {
        const auto ipv4_result = validate_ipv4_header_checksum(packet_bytes, details, packet);
        append_checksum_line(sections.summary_lines, QStringLiteral("IPv4 checksum"), ipv4_result);
        const auto warning = checksum_warning_text(QStringLiteral("IPv4 checksum"), ipv4_result);
        if (!warning.isEmpty()) {
            sections.warnings.push_back(warning);
        }
    }

    if (details.has_tcp) {
        const auto tcp_result = validate_tcp_checksum(packet_bytes, details, packet);
        append_checksum_line(sections.summary_lines, QStringLiteral("TCP checksum"), tcp_result);
        const auto warning = checksum_warning_text(QStringLiteral("TCP checksum"), tcp_result);
        if (!warning.isEmpty()) {
            sections.warnings.push_back(warning);
        }
    }

    if (details.has_udp) {
        const auto udp_result = validate_udp_checksum(packet_bytes, details, packet);
        append_checksum_line(sections.summary_lines, QStringLiteral("UDP checksum"), udp_result);
        const auto warning = checksum_warning_text(QStringLiteral("UDP checksum"), udp_result);
        if (!warning.isEmpty()) {
            sections.warnings.push_back(warning);
        }
    }

    return sections;
}

QString format_byte_count_text(const qulonglong count) {
    return QStringLiteral("%1 %2")
        .arg(count)
        .arg(count == 1U ? QStringLiteral("byte") : QStringLiteral("bytes"));
}

QString packet_byte_view_state_text(const QString& state) {
    if (state == QStringLiteral("complete")) {
        return QStringLiteral("Complete");
    }
    if (state == QStringLiteral("partial")) {
        return QStringLiteral("Partial");
    }
    if (state == QStringLiteral("truncated")) {
        return QStringLiteral("Truncated");
    }
    return QStringLiteral("Unavailable");
}

QString packet_byte_view_contributing_unit_text(const QString& unit_kind, const qulonglong count) {
    if (unit_kind == QStringLiteral("tcp_segment")) {
        return count == 1ULL ? QStringLiteral("TCP segment") : QStringLiteral("TCP segments");
    }
    if (unit_kind == QStringLiteral("quic_crypto_frame")) {
        return count == 1ULL ? QStringLiteral("CRYPTO frame") : QStringLiteral("CRYPTO frames");
    }
    return count == 1ULL ? QStringLiteral("unit") : QStringLiteral("units");
}

QString packet_byte_view_status_text(
    const QString& state,
    const QString& assembly_kind,
    const QVariant& contributing_unit_count,
    const QVariant& contributing_unit_kind,
    const qulonglong available_length,
    const QVariant& declared_length
) {
    QString status = packet_byte_view_state_text(state);
    if (assembly_kind == QStringLiteral("reassembled")) {
        status += QStringLiteral(" • Reassembled");
        if (contributing_unit_count.isValid() && contributing_unit_kind.isValid()) {
            const auto count = contributing_unit_count.toULongLong();
            status += QStringLiteral(" from %1 %2")
                .arg(count)
                .arg(packet_byte_view_contributing_unit_text(contributing_unit_kind.toString(), count));
        }
    }
    status += QStringLiteral(" • Available: ") + format_byte_count_text(available_length);
    if (declared_length.isValid()) {
        status += QStringLiteral(" • Declared: ") + format_byte_count_text(declared_length.toULongLong());
    }
    return status;
}

QVariant optional_length_variant(const std::optional<std::uint32_t>& value) {
    return value.has_value()
        ? QVariant::fromValue<qulonglong>(static_cast<qulonglong>(*value))
        : QVariant {};
}

QVariant optional_length_variant(const std::optional<std::uint64_t>& value) {
    return value.has_value()
        ? QVariant::fromValue<qulonglong>(static_cast<qulonglong>(*value))
        : QVariant {};
}

QVariantList packet_byte_view_descriptors_to_variant_list(
    const std::vector<session_detail::SelectedPacketByteViewPresentationDescriptor>& descriptors
) {
    QVariantList items {};
    items.reserve(static_cast<qsizetype>(descriptors.size()));
    for (const auto& descriptor : descriptors) {
        QVariantMap item {};
        item.insert(QStringLiteral("stableId"), QString::fromStdString(descriptor.stable_id));
        item.insert(QStringLiteral("label"), QString::fromStdString(descriptor.label));
        item.insert(QStringLiteral("depth"), static_cast<int>(descriptor.depth));
        item.insert(QStringLiteral("ownerKind"), QString::fromStdString(descriptor.owner_kind));
        item.insert(QStringLiteral("role"), QString::fromStdString(descriptor.role));
        item.insert(QStringLiteral("assemblyKind"), QString::fromStdString(descriptor.assembly_kind));
        item.insert(QStringLiteral("availableLength"), QVariant::fromValue<qulonglong>(descriptor.available_length));
        item.insert(QStringLiteral("declaredLength"), optional_length_variant(descriptor.declared_length));
        item.insert(QStringLiteral("state"), QString::fromStdString(descriptor.state));
        item.insert(QStringLiteral("supportsPayloadOnly"), descriptor.supports_payload_only);
        item.insert(QStringLiteral("payloadAvailableLength"), optional_length_variant(descriptor.payload_available_length));
        item.insert(QStringLiteral("payloadDeclaredLength"), optional_length_variant(descriptor.payload_declared_length));
        if (descriptor.payload_state.has_value()) {
            item.insert(QStringLiteral("payloadState"), QString::fromStdString(*descriptor.payload_state));
        }
        item.insert(QStringLiteral("contributingUnitCount"), optional_length_variant(descriptor.contributing_unit_count));
        if (descriptor.contributing_unit_kind.has_value()) {
            item.insert(QStringLiteral("contributingUnitKind"), QString::fromStdString(*descriptor.contributing_unit_kind));
        }
        item.insert(QStringLiteral("statusText"), packet_byte_view_status_text(
            QString::fromStdString(descriptor.state),
            QString::fromStdString(descriptor.assembly_kind),
            optional_length_variant(descriptor.contributing_unit_count),
            descriptor.contributing_unit_kind.has_value()
                ? QVariant(QString::fromStdString(*descriptor.contributing_unit_kind))
                : QVariant {},
            descriptor.available_length,
            optional_length_variant(descriptor.declared_length)
        ));
        if (descriptor.parent_stable_id.has_value()) {
            item.insert(QStringLiteral("parentStableId"), QString::fromStdString(*descriptor.parent_stable_id));
        }
        if (descriptor.quic_crypto_stream_offset.has_value()) {
            item.insert(
                QStringLiteral("quicCryptoStreamOffset"),
                QVariant::fromValue<qulonglong>(*descriptor.quic_crypto_stream_offset)
            );
        }
        items.push_back(item);
    }
    return items;
}

std::optional<session_detail::SelectedPacketByteViewId> resolve_selected_packet_byte_view_id(
    const std::vector<session_detail::SelectedPacketByteViewPresentationDescriptor>& descriptors,
    const QString& preferred_stable_id
) {
    auto find_by_stable_id = [&](const QString& stable_id) -> std::optional<session_detail::SelectedPacketByteViewId> {
        if (stable_id.isEmpty()) {
            return std::nullopt;
        }
        const auto stable_id_std = stable_id.toStdString();
        const auto it = std::find_if(
            descriptors.begin(),
            descriptors.end(),
            [&](const session_detail::SelectedPacketByteViewPresentationDescriptor& descriptor) {
                return descriptor.stable_id == stable_id_std;
            }
        );
        if (it == descriptors.end()) {
            return std::nullopt;
        }
        return session_detail::parse_selected_packet_byte_view_stable_id(it->stable_id);
    };

    if (const auto preferred = find_by_stable_id(preferred_stable_id); preferred.has_value()) {
        return preferred;
    }

    const auto frame_it = std::find_if(
        descriptors.begin(),
        descriptors.end(),
        [](const session_detail::SelectedPacketByteViewPresentationDescriptor& descriptor) {
            return descriptor.stable_id == "frame:0:0";
        }
    );
    if (frame_it != descriptors.end()) {
        return session_detail::parse_selected_packet_byte_view_stable_id(frame_it->stable_id);
    }

    if (!descriptors.empty()) {
        return session_detail::parse_selected_packet_byte_view_stable_id(descriptors.front().stable_id);
    }

    return std::nullopt;
}

QString format_stream_source_packets(
    const StreamItemRow& item,
    const std::map<std::uint64_t, std::uint64_t>& flowPacketNumbers
) {
    std::vector<std::uint64_t> flow_numbers {};
    flow_numbers.reserve(item.packet_indices.size());
    for (const auto packet_index : item.packet_indices) {
        const auto flow_it = flowPacketNumbers.find(packet_index);
        if (flow_it == flowPacketNumbers.end()) {
            flow_numbers.clear();
            break;
        }

        flow_numbers.push_back(flow_it->second);
    }

    const auto& packet_numbers = !flow_numbers.empty() ? flow_numbers : item.packet_indices;

    QStringList values {};
    values.reserve(static_cast<qsizetype>(packet_numbers.size()));
    for (const auto number : packet_numbers) {
        values.push_back(QStringLiteral("#%1").arg(number));
    }

    if (values.isEmpty()) {
        return item.packet_count == 1U
            ? QStringLiteral("1 packet")
            : QStringLiteral("%1 packets").arg(item.packet_count);
    }

    return values.size() == 1
        ? QStringLiteral("packet %1").arg(values.join(QString {}))
        : QStringLiteral("packets %1").arg(values.join(QStringLiteral(",")));
}

QString stream_item_details_source(const StreamItemRow& item) {
    return QString::fromStdString(session_detail::stream_item_details_source_text(item));
}

QString stream_item_header_primary_text(const StreamItemRow& item) {
    return QString::fromStdString(item.label);
}

QString stream_item_header_secondary_text(
    const StreamItemRow& item,
    const std::map<std::uint64_t, std::uint64_t>& flowPacketNumbers
) {
    return QStringLiteral("%1 bytes \u2022 %2")
        .arg(item.byte_count)
        .arg(format_stream_source_packets(item, flowPacketNumbers));
}

QString stream_item_header_badge_text(const StreamItemRow& item) {
    if (item.has_constricted_contribution) {
        return QStringLiteral("Constricted");
    }
    if (item.tls_semantic_kind == TlsStreamItemSemanticKind::partial_record ||
        item.tls_semantic_kind == TlsStreamItemSemanticKind::partial_payload ||
        (item.http_summary.has_value() && item.http_summary->semantic_kind == HttpStreamItemSemanticKind::partial_payload) ||
        item.materialization_stability == StreamMaterializationStability::window_incomplete) {
        return QStringLiteral("Partial");
    }
    if (session_detail::stream_item_uses_packet_fallback(item)) {
        return QStringLiteral("Packet fallback");
    }
    if (item.packet_count > 1U) {
        return QStringLiteral("Reassembled");
    }
    return {};
}

QStringList stream_item_constricted_summary_lines(const StreamItemRow& item) {
    if (!item.has_constricted_contribution && item.constricted_packet_notes.empty()) {
        return {};
    }

    QStringList lines {};
    if (!item.constricted_contribution_notes.empty()) {
        lines.push_back(item.constricted_contribution_notes.size() == 1U
            ? QStringLiteral("Constricted contribution: %1").arg(QString::fromStdString(item.constricted_contribution_notes.front()))
            : QStringLiteral("Constricted contributions:"));

        if (item.constricted_contribution_notes.size() > 1U) {
            for (const auto& note : item.constricted_contribution_notes) {
                lines.push_back(QStringLiteral("%1").arg(QString::fromStdString(note)));
            }
        }
    }

    for (const auto& note : item.constricted_packet_notes) {
        lines.push_back(QString::fromStdString(note));
    }

    return lines;
}

QString stream_item_data_tab_title() {
    return QStringLiteral("Item Data");
}

QString stream_item_data_materialization_failure_text() {
    return QStringLiteral("Item data unavailable • Failed to materialize the selected item bytes.");
}

QString source_capture_unavailable_status_text() {
    return QStringLiteral("Original source capture is unavailable. Metadata views remain available, but raw bytes, stream reconstruction, and flow export are disabled.");
}

QString source_capture_unavailable_packet_summary_text() {
    return QStringLiteral(
        "Original source capture unavailable.\n\n"
        "Byte-backed packet details are unavailable for this session.\n\n"
        "Reattach the original capture file to inspect packet byte views and protocol details.");
}

QString source_capture_unavailable_packet_raw_text() {
    return QStringLiteral("Raw packet bytes are unavailable because the original source capture cannot be read.");
}

QString source_capture_unavailable_stream_summary_text() {
    return QStringLiteral(
        "Original source capture unavailable.\n\n"
        "Stream reconstruction requires source packet bytes.\n\n"
        "Reattach the original capture file to inspect stream items and stream-backed details.");
}

QVariantMap packet_summary_field_to_variant_map(const session_detail::PacketSummaryField& field) {
    QVariantMap map {};
    map.insert(QStringLiteral("label"), QString::fromStdString(field.label));
    map.insert(QStringLiteral("value"), QString::fromStdString(field.value));
    return map;
}

QVariantMap packet_summary_layer_to_variant_map(const session_detail::PacketSummaryLayer& layer) {
    QVariantMap map {};
    QVariantList fields {};
    fields.reserve(static_cast<qsizetype>(layer.fields.size()));
    for (const auto& field : layer.fields) {
        fields.push_back(packet_summary_field_to_variant_map(field));
    }

    QVariantList children {};
    children.reserve(static_cast<qsizetype>(layer.children.size()));
    for (const auto& child : layer.children) {
        children.push_back(packet_summary_layer_to_variant_map(child));
    }

    map.insert(QStringLiteral("id"), QString::fromStdString(layer.id));
    map.insert(QStringLiteral("title"), QString::fromStdString(layer.title));
    map.insert(QStringLiteral("fields"), fields);
    map.insert(QStringLiteral("children"), children);
    map.insert(QStringLiteral("expanded_by_default"), layer.expanded_by_default);
    map.insert(QStringLiteral("warning"), layer.warning);
    map.insert(QStringLiteral("marker_text"), QString::fromStdString(layer.marker_text));
    return map;
}

QVariantList packet_summary_layers_to_variant_list(const std::vector<session_detail::PacketSummaryLayer>& layers) {
    QVariantList result {};
    result.reserve(static_cast<qsizetype>(layers.size()));
    for (const auto& layer : layers) {
        result.push_back(packet_summary_layer_to_variant_map(layer));
    }
    return result;
}

QString qstring_from_utf8(const std::string& text) {
    return QString::fromStdString(text);
}

QVariant optional_u64_variant(const std::optional<std::uint64_t>& value) {
    return value.has_value() ? QVariant::fromValue<qulonglong>(*value) : QVariant {};
}

QVariant optional_double_variant(const std::optional<double>& value) {
    return value.has_value() ? QVariant::fromValue(*value) : QVariant {};
}

QVariantList direction_distribution_rows_to_variant_list(
    const std::vector<FrontendDirectionDistributionRowDto>& rows
) {
    QVariantList list {};
    list.reserve(static_cast<qsizetype>(rows.size()));
    for (const auto& row : rows) {
        QVariantMap map {};
        map.insert(QStringLiteral("stableId"), qstring_from_utf8(row.stable_id));
        map.insert(QStringLiteral("label"), qstring_from_utf8(row.label));
        map.insert(QStringLiteral("flowCount"), QVariant::fromValue<qulonglong>(row.flow_count));
        map.insert(QStringLiteral("flowFraction"), row.flow_fraction);
        map.insert(QStringLiteral("flowCountText"), qstring_from_utf8(row.flow_count_text));
        map.insert(QStringLiteral("percentText"), qstring_from_utf8(row.percent_text));
        list.push_back(map);
    }
    return list;
}

QVariantMap capture_time_statistics_to_variant_map(const FrontendCaptureTimeStatisticsDto& statistics) {
    QVariantMap map {};
    map.insert(QStringLiteral("available"), statistics.available);
    map.insert(QStringLiteral("captureStartTimestampUs"), optional_u64_variant(statistics.capture_start_timestamp_us));
    map.insert(QStringLiteral("captureStartText"), qstring_from_utf8(statistics.capture_start_text));
    map.insert(QStringLiteral("captureEndTimestampUs"), optional_u64_variant(statistics.capture_end_timestamp_us));
    map.insert(QStringLiteral("captureEndText"), qstring_from_utf8(statistics.capture_end_text));
    map.insert(QStringLiteral("durationUs"), optional_u64_variant(statistics.duration_us));
    map.insert(QStringLiteral("durationText"), qstring_from_utf8(statistics.duration_text));
    return map;
}

QVariantMap capture_metrics_to_variant_map(const FrontendCaptureMetricsDto& metrics) {
    QVariantMap map {};
    map.insert(QStringLiteral("averageCapturedPacketSize"), optional_double_variant(metrics.average_captured_packet_size));
    map.insert(QStringLiteral("averageCapturedPacketSizeText"), qstring_from_utf8(metrics.average_captured_packet_size_text));
    map.insert(QStringLiteral("averageOriginalPacketSize"), optional_double_variant(metrics.average_original_packet_size));
    map.insert(QStringLiteral("averageOriginalPacketSizeText"), qstring_from_utf8(metrics.average_original_packet_size_text));
    map.insert(QStringLiteral("averagePacketRate"), optional_double_variant(metrics.average_packet_rate));
    map.insert(QStringLiteral("averagePacketRateText"), qstring_from_utf8(metrics.average_packet_rate_text));
    map.insert(QStringLiteral("averageCapturedDataRate"), optional_double_variant(metrics.average_captured_data_rate));
    map.insert(QStringLiteral("averageCapturedDataRateText"), qstring_from_utf8(metrics.average_captured_data_rate_text));
    map.insert(QStringLiteral("averageOriginalDataRate"), optional_double_variant(metrics.average_original_data_rate));
    map.insert(QStringLiteral("averageOriginalDataRateText"), qstring_from_utf8(metrics.average_original_data_rate_text));
    map.insert(QStringLiteral("truncatedPacketCount"), QVariant::fromValue<qulonglong>(metrics.truncated_packet_count));
    map.insert(QStringLiteral("truncatedPacketFraction"), metrics.truncated_packet_fraction);
    map.insert(QStringLiteral("truncatedPacketsText"), qstring_from_utf8(metrics.truncated_packets_text));
    map.insert(QStringLiteral("notCapturedBytes"), QVariant::fromValue<qulonglong>(metrics.not_captured_bytes));
    map.insert(QStringLiteral("notCapturedBytesText"), qstring_from_utf8(metrics.not_captured_bytes_text));
    map.insert(QStringLiteral("captureCompleteness"), optional_double_variant(metrics.capture_completeness));
    map.insert(QStringLiteral("captureCompletenessText"), qstring_from_utf8(metrics.capture_completeness_text));
    return map;
}

QVariantMap flow_characteristics_to_variant_map(const FrontendFlowCharacteristicsDto& statistics) {
    QVariantMap map {};
    map.insert(QStringLiteral("totalFlowCount"), QVariant::fromValue<qulonglong>(statistics.total_flow_count));
    map.insert(QStringLiteral("onlyAToBFlowCount"), QVariant::fromValue<qulonglong>(statistics.only_a_to_b_flow_count));
    map.insert(QStringLiteral("onlyAToBFlowFraction"), statistics.only_a_to_b_flow_fraction);
    map.insert(QStringLiteral("onlyAToBFlowsText"), qstring_from_utf8(statistics.only_a_to_b_flows_text));
    map.insert(
        QStringLiteral("serviceRecognizedFlowCount"),
        QVariant::fromValue<qulonglong>(statistics.service_recognized_flow_count)
    );
    map.insert(QStringLiteral("serviceRecognizedFlowFraction"), statistics.service_recognized_flow_fraction);
    map.insert(QStringLiteral("serviceRecognizedFlowsText"), qstring_from_utf8(statistics.service_recognized_flows_text));
    return map;
}

QVariantMap direction_distribution_to_variant_map(const FrontendDirectionDistributionDto& distribution) {
    QVariantMap map {};
    map.insert(QStringLiteral("totalFlowCount"), QVariant::fromValue<qulonglong>(distribution.total_flow_count));
    map.insert(QStringLiteral("helpText"), qstring_from_utf8(distribution.help_text));
    map.insert(QStringLiteral("rows"), direction_distribution_rows_to_variant_list(distribution.rows));
    return map;
}

QString format_duration_us(const std::uint64_t duration_us) {
    if (duration_us == 0U) {
        return QStringLiteral("0 us");
    }

    if (duration_us < 1000U) {
        return QStringLiteral("%1 us").arg(duration_us);
    }

    if (duration_us < 1000000U) {
        return QStringLiteral("%1 ms").arg(static_cast<double>(duration_us) / 1000.0, 0, 'f', 3);
    }

    return QStringLiteral("%1 s").arg(static_cast<double>(duration_us) / 1000000.0, 0, 'f', 3);
}

QString format_duration_ms(const std::uint64_t duration_us) {
    return QStringLiteral("%1 ms").arg(static_cast<double>(duration_us) / 1000.0, 0, 'f', 3);
}

QString trim_trailing_zeros(QString text) {
    const auto decimal_index = text.indexOf(QLatin1Char('.'));
    if (decimal_index < 0) {
        return text;
    }

    while (text.endsWith(QLatin1Char('0'))) {
        text.chop(1);
    }
    if (text.endsWith(QLatin1Char('.'))) {
        text.chop(1);
    }

    return text;
}

QString format_rate_graph_window_text(const std::uint64_t window_us) {
    if (window_us == 0U) {
        return {};
    }

    if (window_us < 1000000U) {
        const auto window_ms = static_cast<double>(window_us) / 1000.0;
        return QStringLiteral("Window: %1 ms (auto)").arg(trim_trailing_zeros(QString::number(window_ms, 'f', 3)));
    }

    const auto window_seconds = static_cast<double>(window_us) / 1000000.0;
    return QStringLiteral("Window: %1 s (auto)").arg(trim_trailing_zeros(QString::number(window_seconds, 'f', 3)));
}

QString group_integer_part(QString text) {
    const auto decimal_index = text.indexOf(QLatin1Char('.'));
    const QString fraction = decimal_index >= 0 ? text.mid(decimal_index) : QString {};
    QString integer_part = decimal_index >= 0 ? text.left(decimal_index) : text;

    const bool negative = integer_part.startsWith(QLatin1Char('-'));
    if (negative) {
        integer_part.remove(0, 1);
    }

    for (qsizetype index = integer_part.size() - 3; index > 0; index -= 3) {
        integer_part.insert(index, QLatin1Char(' '));
    }

    if (negative) {
        integer_part.prepend(QLatin1Char('-'));
    }

    return integer_part + fraction;
}

QString format_grouped_integer(const std::uint64_t value) {
    return group_integer_part(QString::number(value));
}

QString format_grouped_decimal(const double value, const int decimals) {
    return group_integer_part(trim_trailing_zeros(QString::number(value, 'f', decimals)));
}

QString format_rate_value(const double value, const QString& suffix) {
    return QStringLiteral("%1 %2").arg(value, 0, 'f', 3).arg(suffix);
}

QString format_human_readable_bytes(const double value, const QString& suffix = QString {}) {
    static const std::array<const char*, 5> units = {"B", "KB", "MB", "GB", "TB"};

    double scaled_value = std::max(0.0, value);
    std::size_t unit_index = 0;
    while (scaled_value >= 1024.0 && unit_index + 1 < units.size()) {
        scaled_value /= 1024.0;
        ++unit_index;
    }

    QString numeric_text {};
    if (unit_index == 0) {
        const auto rounded_value = std::round(scaled_value);
        numeric_text = std::fabs(scaled_value - rounded_value) < 0.05
            ? format_grouped_integer(static_cast<std::uint64_t>(std::llround(rounded_value)))
            : format_grouped_decimal(scaled_value, 1);
    } else {
        numeric_text = format_grouped_decimal(scaled_value, 1);
    }

    return QStringLiteral("%1 %2%3")
        .arg(numeric_text, QString::fromLatin1(units[unit_index]), suffix);
}

QString format_byte_rate_value(const double value) {
    return format_human_readable_bytes(value, QStringLiteral("/s"));
}

QString format_size_value(const double value) {
    return format_human_readable_bytes(value);
}

QString format_size_value(const std::uint32_t value) {
    return format_human_readable_bytes(value);
}

QString format_size_value(const std::uint64_t value) {
    return format_human_readable_bytes(static_cast<double>(value));
}

QString format_packet_rate_for_duration(const std::uint64_t packet_count, const std::uint64_t duration_us) {
    const auto packets_per_second = duration_us > 0U
        ? (static_cast<double>(packet_count) * 1000000.0) / static_cast<double>(duration_us)
        : 0.0;
    return format_rate_value(packets_per_second, QStringLiteral("pkt/s"));
}

QString format_data_rate_for_duration(const std::uint64_t byte_count, const std::uint64_t duration_us) {
    const auto bytes_per_second = duration_us > 0U
        ? (static_cast<double>(byte_count) * 1000000.0) / static_cast<double>(duration_us)
        : 0.0;
    return format_byte_rate_value(bytes_per_second);
}

QVariantList make_analysis_rate_series(const std::vector<FlowAnalysisRatePoint>& points) {
    QVariantList rows {};
    rows.reserve(static_cast<qsizetype>(points.size()));

    for (const auto& point : points) {
        QVariantMap row {};
        row.insert(QStringLiteral("xUs"), static_cast<qulonglong>(point.relative_time_us));
        row.insert(QStringLiteral("xSeconds"), static_cast<double>(point.relative_time_us) / 1000000.0);
        row.insert(QStringLiteral("dataPerSecond"), point.data_per_second);
        row.insert(QStringLiteral("packetsPerSecond"), point.packets_per_second);
        rows.push_back(row);
    }

    return rows;
}
QString format_average_packet_size_for_direction(const std::uint64_t byte_count, const std::uint64_t packet_count) {
    const auto average_packet_size = packet_count > 0U
        ? static_cast<double>(byte_count) / static_cast<double>(packet_count)
        : 0.0;
    return format_size_value(average_packet_size);
}

QString buildStreamItemSummary(
    const StreamItemRow& item,
    const std::map<std::uint64_t, std::uint64_t>& flowPacketNumbers
) {
    const auto sourcePackets = format_stream_source_packets(item, flowPacketNumbers);
    const auto sourcePacketsLine = sourcePackets.startsWith(QStringLiteral("packet "))
        ? QStringLiteral("Source packet: %1").arg(sourcePackets.sliced(7))
        : sourcePackets.startsWith(QStringLiteral("packets "))
            ? QStringLiteral("Source packets: %1").arg(sourcePackets.sliced(8))
            : QStringLiteral("Source packets: %1").arg(sourcePackets);

    if (!item.summary_text.empty()) {
        return QStringList {
            QString::fromStdString(item.summary_text),
            QString {},
            QStringLiteral("Stream item: #%1").arg(item.stream_item_index),
            QStringLiteral("Direction: %1").arg(QString::fromStdString(item.direction_text)),
            sourcePacketsLine,
        }.join(QLatin1Char('\n'));
    }

    QStringList lines {
        QStringLiteral("Label: %1").arg(QString::fromStdString(item.label)),
        QStringLiteral("Size: %1 bytes").arg(item.byte_count),
        sourcePacketsLine,
        QStringLiteral("Details source: %1").arg(stream_item_details_source(item)),
    };

    if (const auto constrictedLines = stream_item_constricted_summary_lines(item); !constrictedLines.isEmpty()) {
        lines.push_back(QString {});
        lines.append(constrictedLines);
    }

    return lines.join(QLatin1Char('\n'));
}

QString format_partial_open_warning_message(const OpenFailureInfo& failure) {
    QString message = QStringLiteral("Capture opened partially.");

    if (failure.has_file_offset || failure.has_packet_index || !failure.reason.empty()) {
        message += QStringLiteral(" Import stopped");
        if (failure.has_file_offset) {
            message += QStringLiteral(" at offset %1").arg(failure.file_offset);
        }
        if (failure.has_packet_index) {
            message += failure.has_file_offset
                ? QStringLiteral(" (packet %1)").arg(failure.packet_index)
                : QStringLiteral(" at packet %1").arg(failure.packet_index);
        }
        if (!failure.reason.empty()) {
            message += QStringLiteral(": %1").arg(QString::fromStdString(failure.reason));
        }
        message += QLatin1Char('.');
    }

    message += QStringLiteral(" Results are incomplete.");
    return message;
}

QString buildPacketSummary(
    const PacketDetails& details,
    const PacketRef& packet,
    const PacketChecksumSections& checksum_sections = {},
    const TransportPayloadLengths& payload_lengths = {}
) {
    QStringList lines {};
    const auto packet_number_in_file = details.packet_index + 1U;

    appendSection(lines, QStringLiteral("Packet"), {
        QStringLiteral("Packet number in file: %1").arg(packet_number_in_file),
        QStringLiteral("Time: %1").arg(QString::fromStdString(session_detail::format_packet_timestamp_full(packet))),
        QStringLiteral("Captured Length: %1").arg(details.captured_length),
        QStringLiteral("Original Length: %1").arg(details.original_length),
    });

    QStringList warnings {};
    if (payload_lengths.is_ip_fragmented.value_or(false)) {
        warnings.push_back(QStringLiteral("Packet is IP-fragmented"));
    }
    if (details.captured_length != details.original_length) {
        warnings.push_back(QStringLiteral("Packet is truncated in capture"));
        warnings.push_back(QStringLiteral("Captured Length: %1").arg(details.captured_length));
        warnings.push_back(QStringLiteral("Original Length: %1").arg(details.original_length));
    }
    if (details.ipv4_bounds_from_captured_bytes) {
        warnings.push_back(QStringLiteral("IPv4 total length is unavailable; packet was parsed using captured bytes only"));
        warnings.push_back(QStringLiteral("Header interpretation is conservative (possible pre-offload packet)"));
    }
    warnings.append(checksum_sections.warnings);
    appendSection(lines, QStringLiteral("Warnings"), warnings);
    appendSection(lines, QStringLiteral("Checksums"), checksum_sections.summary_lines);

    if (details.has_ethernet) {
        appendSection(lines, QStringLiteral("Ethernet"), {
            QStringLiteral("EtherType: %1").arg(formatHex16(details.ethernet.ether_type)),
        });
    }

    if (details.has_vlan) {
        QStringList values {};
        values.push_back(QStringLiteral("Tags: %1").arg(details.vlan_tags.size()));
        for (std::size_t index = 0; index < details.vlan_tags.size(); ++index) {
            const auto& tag = details.vlan_tags[index];
            values.push_back(QStringLiteral("VLAN[%1] TCI: %2").arg(index).arg(tag.tci));
            values.push_back(QStringLiteral("VLAN[%1] Encapsulated EtherType: %2").arg(index).arg(formatHex16(tag.encapsulated_ether_type)));
        }
        appendSection(lines, QStringLiteral("VLAN"), values);
    }

    if (details.has_arp) {
        QStringList arp_lines {};
        const auto shared_lines = session_detail::build_basic_summary_lines(details);
        arp_lines.reserve(static_cast<qsizetype>(shared_lines.size()));
        for (const auto& line : shared_lines) {
            arp_lines.push_back(QString::fromStdString(line));
        }
        appendSection(lines, QStringLiteral("ARP"), arp_lines);
    }

    if (details.has_ipv4) {
        appendSection(lines, QStringLiteral("IPv4"), {
            QStringLiteral("Source: %1").arg(formatIpv4Address(details.ipv4.src_addr)),
            QStringLiteral("Destination: %1").arg(formatIpv4Address(details.ipv4.dst_addr)),
            QStringLiteral("Protocol: %1").arg(formatProtocol(details.ipv4.protocol)),
        });
    }

    if (details.has_ipv6) {
        appendSection(lines, QStringLiteral("IPv6"), {
            QStringLiteral("Source: %1").arg(formatIpv6Address(details.ipv6.src_addr)),
            QStringLiteral("Destination: %1").arg(formatIpv6Address(details.ipv6.dst_addr)),
            QStringLiteral("Next Header: %1").arg(formatProtocol(details.ipv6.next_header)),
        });
    }

    if (details.has_tcp) {
        QStringList tcp_lines {
            QStringLiteral("Source Port: %1").arg(details.tcp.src_port),
            QStringLiteral("Destination Port: %1").arg(details.tcp.dst_port),
            QStringLiteral("Flags: %1").arg(formatTcpFlags(details.tcp.flags)),
        };
        if (payload_lengths.original_payload_length.has_value()) {
            if (payload_lengths.real_payload_length.has_value() &&
                *payload_lengths.real_payload_length != *payload_lengths.original_payload_length) {
                tcp_lines.push_back(QStringLiteral("Real Payload Length: %1").arg(*payload_lengths.real_payload_length));
                tcp_lines.push_back(QStringLiteral("Original Payload Length: %1").arg(*payload_lengths.original_payload_length));
            } else {
                tcp_lines.push_back(QStringLiteral("Payload Length: %1").arg(*payload_lengths.original_payload_length));
            }
        } else if (payload_lengths.real_payload_length.has_value()) {
            tcp_lines.push_back(QStringLiteral("Payload Length: %1").arg(*payload_lengths.real_payload_length));
        }
        appendSection(lines, QStringLiteral("TCP"), tcp_lines);
    }

    if (details.has_udp) {
        QStringList udp_lines {
            QStringLiteral("Source Port: %1").arg(details.udp.src_port),
            QStringLiteral("Destination Port: %1").arg(details.udp.dst_port),
        };
        if (payload_lengths.original_payload_length.has_value()) {
            if (payload_lengths.real_payload_length.has_value() &&
                *payload_lengths.real_payload_length != *payload_lengths.original_payload_length) {
                udp_lines.push_back(QStringLiteral("Real Payload Length: %1").arg(*payload_lengths.real_payload_length));
                udp_lines.push_back(QStringLiteral("Original Payload Length: %1").arg(*payload_lengths.original_payload_length));
            } else {
                udp_lines.push_back(QStringLiteral("Payload Length: %1").arg(*payload_lengths.original_payload_length));
            }
        } else if (payload_lengths.real_payload_length.has_value()) {
            udp_lines.push_back(QStringLiteral("Payload Length: %1").arg(*payload_lengths.real_payload_length));
        }
        appendSection(lines, QStringLiteral("UDP"), udp_lines);
    }

    if (details.has_icmp) {
        appendSection(lines, QStringLiteral("ICMP"), {
            QStringLiteral("Type: %1").arg(details.icmp.type),
            QStringLiteral("Code: %1").arg(details.icmp.code),
        });
    }

    if (details.has_icmpv6) {
        appendSection(lines, QStringLiteral("ICMPv6"), {
            QStringLiteral("Type: %1").arg(details.icmpv6.type),
            QStringLiteral("Code: %1").arg(details.icmpv6.code),
        });
    }

    return lines.join(QLatin1Char('\n'));
}

QString buildPacketSummaryFallback(
    const PacketRef& packet,
    const QString& reason_text = {},
    const PacketChecksumSections& checksum_sections = {},
    const std::optional<bool> is_ip_fragmented = std::nullopt
) {
    QStringList lines {};
    const auto packet_number_in_file = packet.packet_index + 1U;

    appendSection(lines, QStringLiteral("Packet"), {
        QStringLiteral("Packet number in file: %1").arg(packet_number_in_file),
        QStringLiteral("Time: %1").arg(QString::fromStdString(session_detail::format_packet_timestamp_full(packet))),
        QStringLiteral("Captured Length: %1").arg(packet.captured_length),
        QStringLiteral("Original Length: %1").arg(packet.original_length),
    });

    QStringList warnings {};
    if (is_ip_fragmented.value_or(false)) {
        warnings.push_back(QStringLiteral("Packet is IP-fragmented"));
    }
    if (packet.captured_length != packet.original_length) {
        warnings.push_back(QStringLiteral("Packet is truncated in capture"));
        warnings.push_back(QStringLiteral("Captured Length: %1").arg(packet.captured_length));
        warnings.push_back(QStringLiteral("Original Length: %1").arg(packet.original_length));
    }
    if (!reason_text.isEmpty()) {
        warnings.push_back(reason_text);
    }
    warnings.append(checksum_sections.warnings);
    appendSection(lines, QStringLiteral("Warnings"), warnings);
    appendSection(lines, QStringLiteral("Checksums"), checksum_sections.summary_lines);

    return lines.join(QLatin1Char('\n'));
}

std::vector<session_detail::PacketSummaryLayer> build_packet_summary_fallback_layers(
    const PacketRef& packet,
    const QString& reason_text = {},
    const PacketChecksumSections& checksum_sections = {},
    const std::optional<bool> is_ip_fragmented = std::nullopt
) {
    std::vector<session_detail::PacketSummaryLayer> layers {};

    std::vector<session_detail::PacketSummaryField> warning_fields {};
    if (is_ip_fragmented.value_or(false)) {
        warning_fields.push_back({});
        warning_fields.back().value = "Packet is IP-fragmented";
    }
    if (packet.captured_length != packet.original_length) {
        warning_fields.push_back({});
        warning_fields.back().value = "Packet is truncated in capture";
        warning_fields.push_back({
            .label = "Captured Length",
            .value = std::to_string(packet.captured_length) + " bytes",
        });
        warning_fields.push_back({
            .label = "Original Length",
            .value = std::to_string(packet.original_length) + " bytes",
        });
    }
    if (!reason_text.isEmpty()) {
        warning_fields.push_back({});
        warning_fields.back().value = reason_text.toStdString();
    }
    for (const auto& warning : checksum_sections.warnings) {
        warning_fields.push_back({
            .value = warning.toStdString(),
        });
    }
    if (!warning_fields.empty()) {
        layers.push_back(session_detail::PacketSummaryLayer {
            .id = "warnings",
            .title = "Warnings",
            .fields = std::move(warning_fields),
            .expanded_by_default = true,
            .warning = true,
            .marker_text = "Warning",
        });
    }

    std::vector<session_detail::PacketSummaryField> frame_fields {};
    frame_fields.push_back({
        .label = "Packet number in file",
        .value = std::to_string(packet.packet_index + 1U),
    });
    frame_fields.push_back({
        .label = "Timestamp",
        .value = session_detail::format_packet_timestamp_full(packet),
    });
    frame_fields.push_back({
        .label = "Captured Length",
        .value = std::to_string(packet.captured_length) + " bytes",
    });
    frame_fields.push_back({
        .label = "Original Length",
        .value = std::to_string(packet.original_length) + " bytes",
    });
    layers.push_back(session_detail::PacketSummaryLayer {
        .id = "frame",
        .title = "Frame: Packet " + std::to_string(packet.packet_index + 1U) + " in file",
        .fields = std::move(frame_fields),
    });

    std::vector<session_detail::PacketSummaryField> checksum_fields {};
    checksum_fields.reserve(static_cast<std::size_t>(checksum_sections.summary_lines.size()));
    for (const auto& line : checksum_sections.summary_lines) {
        checksum_fields.push_back({
            .value = line.toStdString(),
        });
    }
    if (!checksum_fields.empty()) {
        layers.push_back(session_detail::PacketSummaryLayer {
            .id = "checksums",
            .title = "Checksums",
            .fields = std::move(checksum_fields),
        });
    }

    return layers;
}

}  // namespace

MainController::MainController(QObject* parent)
    : QObject(parent)
    , advanced_flow_filter_editor_model_(advanced_flow_filter_document_state_, this)
    , advanced_flow_filter_protocol_path_selector_model_(this)
    , current_tab_index_(kFlowTabIndex)
    , selected_packet_index_(kInvalidPacketSelection) {
    flow_model_.setProtocolPathPresentationResolver([this](const ProtocolPathId protocol_path_id) {
        return session_detail::build_protocol_path_presentation(session_.state().protocol_path_registry, protocol_path_id);
    });
    advanced_flow_filter_protocol_path_selector_model_.setCaptureSession(&session_);
    advanced_flow_filter_editor_model_.setProtocolPathApplicabilityResolver([this](const auto& predicate) {
        return protocol_path_predicate_applicability(session_, predicate);
    });

    QObject::connect(&flow_model_, &FlowListModel::checkedFlowsChanged, this, [this]() {
        emit selectedFlowCountChanged();
        emit actionAvailabilityChanged();
    });
    QObject::connect(
        &advanced_flow_filter_editor_model_,
        &AdvancedFlowFilterEditorModel::stateChanged,
        this,
        &MainController::advancedFlowFilterPresentationChanged
    );
}

MainController::~MainController() {
    cleanupFlowInfoExportThread();
    cleanupSmartExportThread();
    cleanupIndexSaveThread();
    cleanupAnalysisSequenceExportThread();
    cleanupOpenThread();
}

QString MainController::currentInputPath() const {
    return current_input_path_;
}

QString MainController::applicationVersion() const {
    return QCoreApplication::applicationVersion();
}

QString MainController::activeSourceCapturePath() const {
    const auto& path = session_.attached_source_capture_path();
    return path.empty() ? QString {} : QString::fromStdWString(path.wstring());
}

QString MainController::expectedSourceCapturePath() const {
    const auto& path = session_.expected_source_capture_path();
    return path.empty() ? QString {} : QString::fromStdWString(path.wstring());
}
QString MainController::openErrorText() const {
    return open_error_text_;
}

QString MainController::statusText() const {
    return status_text_;
}

bool MainController::statusIsError() const noexcept {
    return status_is_error_;
}

bool MainController::hasCapture() const noexcept {
    return session_.has_capture();
}

bool MainController::hasSourceCapture() const noexcept {
    return session_.has_source_capture() && session_.source_capture_accessible();
}

bool MainController::openedFromIndex() const noexcept {
    return session_.opened_from_index();
}

bool MainController::canAttachSourceCapture() const noexcept {
    return !is_opening_
        && !smart_export_in_progress_
        && !index_save_in_progress_
        && !flow_info_csv_export_in_progress_
        && session_.has_capture()
        && !hasSourceCapture();
}

bool MainController::canSaveIndex() const noexcept {
    return !is_opening_
        && !smart_export_in_progress_
        && !analysis_sequence_export_in_progress_
        && !index_save_in_progress_
        && !flow_info_csv_export_in_progress_
        && session_.has_capture()
        && hasSourceCapture();
}

bool MainController::partialOpen() const noexcept {
    return session_.is_partial_open();
}

QString MainController::partialOpenWarningText() const {
    return session_.is_partial_open()
        ? format_partial_open_warning_message(session_.partial_open_failure())
        : QString {};
}

bool MainController::canExportSelectedFlow() const noexcept {
    return !is_opening_
        && !smart_export_in_progress_
        && !index_save_in_progress_
        && !flow_info_csv_export_in_progress_
        && hasSourceCapture()
        && selected_flow_index_ >= 0;
}

qulonglong MainController::selectedFlowCount() const noexcept {
    return static_cast<qulonglong>(flow_model_.checkedFlowCount());
}

bool MainController::canExportSelectedFlows() const noexcept {
    return !is_opening_
        && !smart_export_in_progress_
        && !index_save_in_progress_
        && !flow_info_csv_export_in_progress_
        && hasSourceCapture()
        && flow_model_.checkedFlowCount() > 0;
}

bool MainController::canExportUnselectedFlows() const noexcept {
    return !is_opening_
        && !smart_export_in_progress_
        && !index_save_in_progress_
        && !flow_info_csv_export_in_progress_
        && hasSourceCapture()
        && flow_model_.totalFlowCount() > flow_model_.checkedFlowCount();
}

bool MainController::canExportAllFlowsInfoCsv() const noexcept {
    return !is_opening_
        && !smart_export_in_progress_
        && !index_save_in_progress_
        && !flow_info_csv_export_in_progress_
        && flow_info_csv_export_thread_ == nullptr
        && hasCapture()
        && flow_model_.totalFlowCount() > 0;
}

bool MainController::isOpening() const noexcept {
    return is_opening_;
}

qulonglong MainController::openProgressPackets() const noexcept {
    return open_progress_packets_;
}

qulonglong MainController::openProgressBytes() const noexcept {
    return open_progress_bytes_;
}

qulonglong MainController::openProgressTotalBytes() const noexcept {
    return open_progress_total_bytes_;
}

double MainController::openProgressPercent() const noexcept {
    return open_progress_percent_;
}

QString MainController::openingInputPath() const {
    return active_open_input_path_;
}

bool MainController::openingAsIndex() const noexcept {
    return active_open_as_index_;
}

QString MainController::openProgressProcessedText() const {
    if (open_progress_total_bytes_ > 0U) {
        const auto percent_text = trim_trailing_zeros(QString::number(std::clamp(open_progress_percent_ * 100.0, 0.0, 100.0), 'f', 1));
        return QStringLiteral("Processed: %1 / %2 (%3%)")
            .arg(format_size_value(static_cast<std::uint64_t>(open_progress_bytes_)))
            .arg(format_size_value(static_cast<std::uint64_t>(open_progress_total_bytes_)))
            .arg(percent_text);
    }

    return QStringLiteral("Processed: %1").arg(format_size_value(static_cast<std::uint64_t>(open_progress_bytes_)));
}

bool MainController::isApplyingSession() const noexcept {
    return is_applying_session_;
}

bool MainController::packetsLoading() const noexcept {
    return packets_loading_;
}

bool MainController::packetsPartiallyLoaded() const noexcept {
    return total_packet_row_count_ > loaded_packet_row_count_;
}

qulonglong MainController::loadedPacketRowCount() const noexcept {
    return static_cast<qulonglong>(loaded_packet_row_count_);
}

qulonglong MainController::totalPacketRowCount() const noexcept {
    return static_cast<qulonglong>(total_packet_row_count_);
}

bool MainController::canLoadMorePackets() const noexcept {
    return (selected_flow_index_ >= 0 || unrecognized_packets_selected_) && loaded_packet_row_count_ < total_packet_row_count_;
}


bool MainController::streamLoading() const noexcept {
    return stream_loading_;
}

bool MainController::streamPartiallyLoaded() const noexcept {
    return can_load_more_stream_items_;
}

qulonglong MainController::loadedStreamItemCount() const noexcept {
    return static_cast<qulonglong>(loaded_stream_item_count_);
}

qulonglong MainController::totalStreamItemCount() const noexcept {
    return static_cast<qulonglong>(total_stream_item_count_);
}

qulonglong MainController::streamPacketWindowCount() const noexcept {
    return static_cast<qulonglong>(stream_packet_window_count_);
}

bool MainController::streamPacketWindowPartial() const noexcept {
    return selected_flow_index_ >= 0 && stream_packet_window_count_ > 0U && stream_packet_window_count_ < total_packet_row_count_;
}

bool MainController::canLoadMoreStreamItems() const noexcept {
    return selected_flow_index_ >= 0 && can_load_more_stream_items_;
}


bool MainController::analysisLoading() const noexcept {
    return analysis_loading_;
}


bool MainController::analysisAvailable() const noexcept {
    return current_flow_analysis_.has_value();
}

bool MainController::analysisRateGraphAvailable() const noexcept {
    return current_flow_analysis_.has_value() && current_flow_analysis_->rate_graph.available;
}

QString MainController::analysisRateGraphStatusText() const {
    if (!current_flow_analysis_.has_value() || current_flow_analysis_->rate_graph.status_text.empty()) {
        return {};
    }

    return QString::fromStdString(current_flow_analysis_->rate_graph.status_text);
}

QString MainController::analysisRateGraphWindowText() const {
    if (!current_flow_analysis_.has_value()) {
        return {};
    }

    return format_rate_graph_window_text(current_flow_analysis_->rate_graph.window_us);
}

QVariantList MainController::analysisRateSeriesAToB() const {
    if (!current_flow_analysis_.has_value()) {
        return {};
    }

    return make_analysis_rate_series(current_flow_analysis_->rate_graph.points_a_to_b);
}

QVariantList MainController::analysisRateSeriesBToA() const {
    if (!current_flow_analysis_.has_value()) {
        return {};
    }

    return make_analysis_rate_series(current_flow_analysis_->rate_graph.points_b_to_a);
}
bool MainController::canExportAnalysisSequence() const noexcept {
    return selected_flow_index_ >= 0
        && !analysis_sequence_export_in_progress_
        && !index_save_in_progress_
        && !flow_info_csv_export_in_progress_;
}

bool MainController::analysisSequenceExportInProgress() const noexcept {
    return analysis_sequence_export_in_progress_;
}

QString MainController::analysisSequenceExportStatusText() const {
    return analysis_sequence_export_status_text_;
}

bool MainController::analysisSequenceExportStatusIsError() const noexcept {
    return analysis_sequence_export_status_is_error_;
}

bool MainController::flowInfoCsvExportInProgress() const noexcept {
    return flow_info_csv_export_in_progress_;
}

bool MainController::smartExportInProgress() const noexcept {
    return smart_export_in_progress_;
}

bool MainController::smartExportCancelRequested() const noexcept {
    return smart_export_cancel_requested_;
}

qulonglong MainController::smartExportProgressPackets() const noexcept {
    return smart_export_progress_packets_;
}

qulonglong MainController::smartExportProgressTotalPackets() const noexcept {
    return smart_export_progress_total_packets_;
}

double MainController::smartExportProgressPercent() const noexcept {
    if (smart_export_progress_total_packets_ == 0U) {
        return 0.0;
    }

    return std::clamp(
        static_cast<double>(smart_export_progress_packets_) / static_cast<double>(smart_export_progress_total_packets_),
        0.0,
        1.0
    );
}

QString MainController::smartExportProgressText() const {
    return smart_export_progress_text_;
}

bool MainController::indexSaveInProgress() const noexcept {
    return index_save_in_progress_;
}

bool MainController::indexSaveCancelRequested() const noexcept {
    return index_save_cancel_requested_;
}

double MainController::indexSaveProgressPercent() const noexcept {
    return index_save_progress_percent_;
}

QString MainController::indexSaveProgressText() const {
    return index_save_progress_text_;
}

QString MainController::analysisDurationText() const {
    return current_flow_analysis_.has_value()
        ? format_duration_us(current_flow_analysis_->duration_us)
        : QString {};
}

QString MainController::analysisTimelineFirstPacketTime() const {
    return current_flow_analysis_.has_value() && !current_flow_analysis_->first_packet_timestamp_text.empty()
        ? QString::fromStdString(current_flow_analysis_->first_packet_timestamp_text)
        : QString {};
}

QString MainController::analysisTimelineLastPacketTime() const {
    return current_flow_analysis_.has_value() && !current_flow_analysis_->last_packet_timestamp_text.empty()
        ? QString::fromStdString(current_flow_analysis_->last_packet_timestamp_text)
        : QString {};
}

QString MainController::analysisTimelineLargestGapText() const {
    return current_flow_analysis_.has_value()
        ? format_duration_us(current_flow_analysis_->largest_gap_us)
        : QString {};
}

qulonglong MainController::analysisTimelinePacketCountConsidered() const noexcept {
    return current_flow_analysis_.has_value()
        ? static_cast<qulonglong>(current_flow_analysis_->timeline_packet_count_considered)
        : 0U;
}

QString MainController::analysisTimelinePacketCountConsideredText() const {
    return current_flow_analysis_.has_value()
        ? format_grouped_integer(current_flow_analysis_->timeline_packet_count_considered)
        : QString {};
}

qulonglong MainController::analysisTotalPackets() const noexcept {
    return current_flow_analysis_.has_value() ? static_cast<qulonglong>(current_flow_analysis_->total_packets) : 0U;
}

QString MainController::analysisTotalPacketsText() const {
    return current_flow_analysis_.has_value()
        ? format_grouped_integer(current_flow_analysis_->total_packets)
        : QString {};
}

qulonglong MainController::analysisTotalBytes() const noexcept {
    return current_flow_analysis_.has_value() ? static_cast<qulonglong>(current_flow_analysis_->total_bytes) : 0U;
}

QString MainController::analysisTotalBytesText() const {
    return current_flow_analysis_.has_value()
        ? format_size_value(current_flow_analysis_->total_bytes)
        : QString {};
}

qulonglong MainController::analysisCapturedBytes() const noexcept {
    if (!current_flow_analysis_.has_value()) {
        return 0U;
    }
    return static_cast<qulonglong>(current_flow_analysis_->captured_bytes);
}

QString MainController::analysisCapturedBytesText() const {
    return current_flow_analysis_.has_value()
        ? format_size_value(static_cast<std::uint64_t>(analysisCapturedBytes()))
        : QString {};
}

QString MainController::analysisEndpointSummaryText() const {
    return current_flow_analysis_.has_value()
        ? selected_flow_endpoint_summary(flow_model_, selected_flow_index_)
        : QString {};
}

QString MainController::analysisPacketsPerSecondText() const {
    return current_flow_analysis_.has_value()
        ? format_rate_value(current_flow_analysis_->packets_per_second, QStringLiteral("pkt/s"))
        : QString {};
}

QString MainController::analysisPacketsPerSecondAToBText() const {
    return current_flow_analysis_.has_value()
        ? format_packet_rate_for_duration(current_flow_analysis_->packets_a_to_b, current_flow_analysis_->duration_us)
        : QString {};
}

QString MainController::analysisPacketsPerSecondBToAText() const {
    return current_flow_analysis_.has_value()
        ? format_packet_rate_for_duration(current_flow_analysis_->packets_b_to_a, current_flow_analysis_->duration_us)
        : QString {};
}

QString MainController::analysisBytesPerSecondText() const {
    return current_flow_analysis_.has_value()
    ? format_byte_rate_value(current_flow_analysis_->bytes_per_second)
        : QString {};
}

QString MainController::analysisBytesPerSecondAToBText() const {
    return current_flow_analysis_.has_value()
        ? format_data_rate_for_duration(current_flow_analysis_->bytes_a_to_b, current_flow_analysis_->duration_us)
        : QString {};
}

QString MainController::analysisBytesPerSecondBToAText() const {
    return current_flow_analysis_.has_value()
        ? format_data_rate_for_duration(current_flow_analysis_->bytes_b_to_a, current_flow_analysis_->duration_us)
        : QString {};
}

QString MainController::analysisAveragePacketSizeText() const {
    return current_flow_analysis_.has_value()
        ? format_size_value(current_flow_analysis_->average_packet_size_bytes)
        : QString {};
}

QString MainController::analysisAveragePacketSizeAToBText() const {
    return current_flow_analysis_.has_value()
        ? format_average_packet_size_for_direction(current_flow_analysis_->bytes_a_to_b, current_flow_analysis_->packets_a_to_b)
        : QString {};
}

QString MainController::analysisAveragePacketSizeBToAText() const {
    return current_flow_analysis_.has_value()
        ? format_average_packet_size_for_direction(current_flow_analysis_->bytes_b_to_a, current_flow_analysis_->packets_b_to_a)
        : QString {};
}

QString MainController::analysisAverageInterArrivalText() const {
    return current_flow_analysis_.has_value()
        ? format_duration_us(static_cast<std::uint64_t>(std::llround(current_flow_analysis_->average_inter_arrival_us)))
        : QString {};
}

QString MainController::analysisMinPacketSizeText() const {
    return current_flow_analysis_.has_value()
        ? format_size_value(current_flow_analysis_->min_packet_size_bytes)
        : QString {};
}

QString MainController::analysisMinPacketSizeAToBText() const {
    return current_flow_analysis_.has_value() && current_flow_analysis_->packets_a_to_b > 0U
        ? format_size_value(current_flow_analysis_->min_packet_size_a_to_b_bytes)
        : QString {};
}

QString MainController::analysisMinPacketSizeBToAText() const {
    return current_flow_analysis_.has_value() && current_flow_analysis_->packets_b_to_a > 0U
        ? format_size_value(current_flow_analysis_->min_packet_size_b_to_a_bytes)
        : QString {};
}

QString MainController::analysisMaxPacketSizeText() const {
    return current_flow_analysis_.has_value()
        ? format_size_value(current_flow_analysis_->max_packet_size_bytes)
        : QString {};
}

QString MainController::analysisMaxCapturedPacketSizeText() const {
    return current_flow_analysis_.has_value()
        ? QString::fromStdString(session_detail::format_statistics_size_value(
            current_flow_analysis_->max_captured_packet_size_bytes
        ))
        : QString {};
}

QString MainController::analysisMaxPacketSizeAToBText() const {
    return current_flow_analysis_.has_value() && current_flow_analysis_->packets_a_to_b > 0U
        ? format_size_value(current_flow_analysis_->max_packet_size_a_to_b_bytes)
        : QString {};
}

QString MainController::analysisMaxPacketSizeBToAText() const {
    return current_flow_analysis_.has_value() && current_flow_analysis_->packets_b_to_a > 0U
        ? format_size_value(current_flow_analysis_->max_packet_size_b_to_a_bytes)
        : QString {};
}

QString MainController::analysisPacketRatioText() const {
    return current_flow_analysis_.has_value() && !current_flow_analysis_->packet_ratio_text.empty()
        ? QString::fromStdString(current_flow_analysis_->packet_ratio_text)
        : QString {};
}

QString MainController::analysisByteRatioText() const {
    return current_flow_analysis_.has_value() && !current_flow_analysis_->byte_ratio_text.empty()
        ? QString::fromStdString(current_flow_analysis_->byte_ratio_text)
        : QString {};
}

QString MainController::analysisPacketDirectionText() const {
    return current_flow_analysis_.has_value() && !current_flow_analysis_->packet_direction_text.empty()
        ? QString::fromStdString(current_flow_analysis_->packet_direction_text)
        : QString {};
}

QString MainController::analysisDataDirectionText() const {
    return current_flow_analysis_.has_value() && !current_flow_analysis_->data_direction_text.empty()
        ? QString::fromStdString(current_flow_analysis_->data_direction_text)
        : QString {};
}

QString MainController::analysisProtocolHint() const {
    return current_flow_analysis_.has_value() && !current_flow_analysis_->protocol_hint.empty()
        ? format_protocol_hint_display(QString::fromStdString(current_flow_analysis_->protocol_hint))
        : QString {};
}

QString MainController::analysisServiceHint() const {
    if (!current_flow_analysis_.has_value()) {
        return {};
    }

    if (!current_flow_analysis_->service_hint.empty()) {
        return QString::fromStdString(current_flow_analysis_->service_hint);
    }

    if (!current_flow_analysis_->protocol_panel_service_text.empty()) {
        return QString::fromStdString(current_flow_analysis_->protocol_panel_service_text);
    }

    return selected_flow_service_hint(flow_model_, selected_flow_index_);
}

QString MainController::analysisProtocolVersionText() const {
    if (!current_flow_analysis_.has_value()) {
        return {};
    }

    if (!current_flow_analysis_->protocol_panel_version_text.empty()) {
        return QString::fromStdString(current_flow_analysis_->protocol_panel_version_text);
    }

    const auto protocol_hint = QString::fromStdString(current_flow_analysis_->protocol_hint);
    if (protocol_hint.compare(QStringLiteral("tls"), Qt::CaseInsensitive) == 0
        || protocol_hint.compare(QStringLiteral("quic"), Qt::CaseInsensitive) == 0) {
        return QStringLiteral("unknown");
    }

    return {};
}

QString MainController::analysisProtocolServiceText() const {
    if (!current_flow_analysis_.has_value()) {
        return {};
    }

    if (!current_flow_analysis_->protocol_panel_service_text.empty()) {
        return QString::fromStdString(current_flow_analysis_->protocol_panel_service_text);
    }

    const auto protocol_hint = QString::fromStdString(current_flow_analysis_->protocol_hint);
    if (protocol_hint.compare(QStringLiteral("tls"), Qt::CaseInsensitive) == 0
        || protocol_hint.compare(QStringLiteral("quic"), Qt::CaseInsensitive) == 0) {
        const auto service_hint = selected_flow_service_hint(flow_model_, selected_flow_index_);
        return service_hint.isEmpty() ? QStringLiteral("unknown") : service_hint;
    }

    return {};
}

QString MainController::analysisProtocolFallbackText() const {
    return current_flow_analysis_.has_value() && !current_flow_analysis_->protocol_panel_fallback_text.empty()
        ? QString::fromStdString(current_flow_analysis_->protocol_panel_fallback_text)
        : QString {};
}

bool MainController::analysisHasTcpControlCounts() const noexcept {
    return current_flow_analysis_.has_value() && current_flow_analysis_->has_tcp_control_counts;
}

qulonglong MainController::analysisTcpSynPackets() const noexcept {
    return current_flow_analysis_.has_value() ? static_cast<qulonglong>(current_flow_analysis_->tcp_syn_packets) : 0U;
}

QString MainController::analysisTcpSynPacketsText() const {
    return current_flow_analysis_.has_value()
        ? format_grouped_integer(current_flow_analysis_->tcp_syn_packets)
        : QString {};
}

qulonglong MainController::analysisTcpFinPackets() const noexcept {
    return current_flow_analysis_.has_value() ? static_cast<qulonglong>(current_flow_analysis_->tcp_fin_packets) : 0U;
}

QString MainController::analysisTcpFinPacketsText() const {
    return current_flow_analysis_.has_value()
        ? format_grouped_integer(current_flow_analysis_->tcp_fin_packets)
        : QString {};
}

qulonglong MainController::analysisTcpRstPackets() const noexcept {
    return current_flow_analysis_.has_value() ? static_cast<qulonglong>(current_flow_analysis_->tcp_rst_packets) : 0U;
}

QString MainController::analysisTcpRstPacketsText() const {
    return current_flow_analysis_.has_value()
        ? format_grouped_integer(current_flow_analysis_->tcp_rst_packets)
        : QString {};
}

qulonglong MainController::analysisBurstCount() const noexcept {
    return current_flow_analysis_.has_value() ? static_cast<qulonglong>(current_flow_analysis_->burst_count) : 0U;
}

QString MainController::analysisBurstCountText() const {
    return current_flow_analysis_.has_value()
        ? format_grouped_integer(current_flow_analysis_->burst_count)
        : QString {};
}

qulonglong MainController::analysisLongestBurstPacketCount() const noexcept {
    return current_flow_analysis_.has_value()
        ? static_cast<qulonglong>(current_flow_analysis_->longest_burst_packet_count)
        : 0U;
}

QString MainController::analysisLongestBurstPacketCountText() const {
    return current_flow_analysis_.has_value()
        ? format_grouped_integer(current_flow_analysis_->longest_burst_packet_count)
        : QString {};
}

QString MainController::analysisLargestBurstBytesText() const {
    return current_flow_analysis_.has_value()
        ? format_size_value(current_flow_analysis_->largest_burst_bytes)
        : QString {};
}

qulonglong MainController::analysisIdleGapCount() const noexcept {
    return current_flow_analysis_.has_value() ? static_cast<qulonglong>(current_flow_analysis_->idle_gap_count) : 0U;
}

QString MainController::analysisIdleGapCountText() const {
    return current_flow_analysis_.has_value()
        ? format_grouped_integer(current_flow_analysis_->idle_gap_count)
        : QString {};
}

QString MainController::analysisLargestIdleGapText() const {
    return current_flow_analysis_.has_value()
        ? format_duration_us(current_flow_analysis_->largest_idle_gap_us)
        : QString {};
}

qulonglong MainController::analysisPacketsAToB() const noexcept {
    return current_flow_analysis_.has_value() ? static_cast<qulonglong>(current_flow_analysis_->packets_a_to_b) : 0U;
}

QString MainController::analysisPacketsAToBText() const {
    return current_flow_analysis_.has_value()
        ? format_grouped_integer(current_flow_analysis_->packets_a_to_b)
        : QString {};
}

qulonglong MainController::analysisPacketsBToA() const noexcept {
    return current_flow_analysis_.has_value() ? static_cast<qulonglong>(current_flow_analysis_->packets_b_to_a) : 0U;
}

QString MainController::analysisPacketsBToAText() const {
    return current_flow_analysis_.has_value()
        ? format_grouped_integer(current_flow_analysis_->packets_b_to_a)
        : QString {};
}

qulonglong MainController::analysisBytesAToB() const noexcept {
    return current_flow_analysis_.has_value() ? static_cast<qulonglong>(current_flow_analysis_->bytes_a_to_b) : 0U;
}

QString MainController::analysisBytesAToBText() const {
    return current_flow_analysis_.has_value()
        ? format_size_value(current_flow_analysis_->bytes_a_to_b)
        : QString {};
}

qulonglong MainController::analysisBytesBToA() const noexcept {
    return current_flow_analysis_.has_value() ? static_cast<qulonglong>(current_flow_analysis_->bytes_b_to_a) : 0U;
}

QString MainController::analysisBytesBToAText() const {
    return current_flow_analysis_.has_value()
        ? format_size_value(current_flow_analysis_->bytes_b_to_a)
        : QString {};
}

QVariantList MainController::analysisInterArrivalHistogram() const {
    return analysisInterArrivalHistogramAll();
}

QVariantList MainController::analysisInterArrivalHistogramAll() const {
    QVariantList rows {};
    if (!current_flow_analysis_.has_value()) {
        return rows;
    }

    rows.reserve(static_cast<qsizetype>(current_flow_analysis_->inter_arrival_histograms.histogram_all.size()));
    for (const auto& histogram_row : current_flow_analysis_->inter_arrival_histograms.histogram_all) {
        QVariantMap row {};
        row.insert(QStringLiteral("bucketLabel"), QString::fromStdString(histogram_row.bucket_label));
        row.insert(QStringLiteral("packetCount"), static_cast<qulonglong>(histogram_row.packet_count));
        row.insert(QStringLiteral("packetCountText"), format_grouped_integer(histogram_row.packet_count));
        rows.push_back(row);
    }

    return rows;
}

QVariantList MainController::analysisInterArrivalHistogramAToB() const {
    QVariantList rows {};
    if (!current_flow_analysis_.has_value()) {
        return rows;
    }

    rows.reserve(static_cast<qsizetype>(current_flow_analysis_->inter_arrival_histograms.histogram_a_to_b.size()));
    for (const auto& histogram_row : current_flow_analysis_->inter_arrival_histograms.histogram_a_to_b) {
        QVariantMap row {};
        row.insert(QStringLiteral("bucketLabel"), QString::fromStdString(histogram_row.bucket_label));
        row.insert(QStringLiteral("packetCount"), static_cast<qulonglong>(histogram_row.packet_count));
        row.insert(QStringLiteral("packetCountText"), format_grouped_integer(histogram_row.packet_count));
        rows.push_back(row);
    }

    return rows;
}

QVariantList MainController::analysisInterArrivalHistogramBToA() const {
    QVariantList rows {};
    if (!current_flow_analysis_.has_value()) {
        return rows;
    }

    rows.reserve(static_cast<qsizetype>(current_flow_analysis_->inter_arrival_histograms.histogram_b_to_a.size()));
    for (const auto& histogram_row : current_flow_analysis_->inter_arrival_histograms.histogram_b_to_a) {
        QVariantMap row {};
        row.insert(QStringLiteral("bucketLabel"), QString::fromStdString(histogram_row.bucket_label));
        row.insert(QStringLiteral("packetCount"), static_cast<qulonglong>(histogram_row.packet_count));
        row.insert(QStringLiteral("packetCountText"), format_grouped_integer(histogram_row.packet_count));
        rows.push_back(row);
    }

    return rows;
}

QVariantList MainController::analysisPacketSizeHistogram() const {
    return analysisPacketSizeHistogramAll();
}

QVariantList MainController::analysisPacketSizeHistogramAll() const {
    QVariantList rows {};
    if (!current_flow_analysis_.has_value()) {
        return rows;
    }

    rows.reserve(static_cast<qsizetype>(current_flow_analysis_->packet_size_histograms.histogram_all.size()));
    for (const auto& histogram_row : current_flow_analysis_->packet_size_histograms.histogram_all) {
        QVariantMap row {};
        row.insert(QStringLiteral("bucketLabel"), QString::fromStdString(histogram_row.bucket_label));
        row.insert(QStringLiteral("packetCount"), static_cast<qulonglong>(histogram_row.packet_count));
        row.insert(QStringLiteral("packetCountText"), format_grouped_integer(histogram_row.packet_count));
        rows.push_back(row);
    }

    return rows;
}

QVariantList MainController::analysisPacketSizeHistogramAToB() const {
    QVariantList rows {};
    if (!current_flow_analysis_.has_value()) {
        return rows;
    }

    rows.reserve(static_cast<qsizetype>(current_flow_analysis_->packet_size_histograms.histogram_a_to_b.size()));
    for (const auto& histogram_row : current_flow_analysis_->packet_size_histograms.histogram_a_to_b) {
        QVariantMap row {};
        row.insert(QStringLiteral("bucketLabel"), QString::fromStdString(histogram_row.bucket_label));
        row.insert(QStringLiteral("packetCount"), static_cast<qulonglong>(histogram_row.packet_count));
        row.insert(QStringLiteral("packetCountText"), format_grouped_integer(histogram_row.packet_count));
        rows.push_back(row);
    }

    return rows;
}

QVariantList MainController::analysisPacketSizeHistogramBToA() const {
    QVariantList rows {};
    if (!current_flow_analysis_.has_value()) {
        return rows;
    }

    rows.reserve(static_cast<qsizetype>(current_flow_analysis_->packet_size_histograms.histogram_b_to_a.size()));
    for (const auto& histogram_row : current_flow_analysis_->packet_size_histograms.histogram_b_to_a) {
        QVariantMap row {};
        row.insert(QStringLiteral("bucketLabel"), QString::fromStdString(histogram_row.bucket_label));
        row.insert(QStringLiteral("packetCount"), static_cast<qulonglong>(histogram_row.packet_count));
        row.insert(QStringLiteral("packetCountText"), format_grouped_integer(histogram_row.packet_count));
        rows.push_back(row);
    }

    return rows;
}

QVariantList MainController::analysisSequencePreview() const {
    QVariantList rows {};
    if (!current_flow_analysis_.has_value()) {
        return rows;
    }

    rows.reserve(static_cast<qsizetype>(current_flow_analysis_->sequence_preview_rows.size()));
    for (const auto& preview_row : current_flow_analysis_->sequence_preview_rows) {
        const QString transport_payload_text = preview_row.payload_length.has_value()
            ? QString::number(*preview_row.payload_length)
            : QStringLiteral("-");

        QVariantMap row {};
        row.insert(QStringLiteral("packetNumber"), static_cast<qulonglong>(preview_row.flow_packet_number));
        row.insert(QStringLiteral("direction"), QString::fromStdString(preview_row.direction_text));
        row.insert(QStringLiteral("deltaTimeText"), format_duration_ms(preview_row.delta_time_us));
        row.insert(QStringLiteral("capturedLength"), preview_row.captured_length);
        row.insert(QStringLiteral("originalLength"), preview_row.original_length);
        row.insert(QStringLiteral("transportPayloadText"), transport_payload_text);
        row.insert(QStringLiteral("timestampText"), QString::fromStdString(preview_row.timestamp_text));
        rows.push_back(row);
    }

    return rows;
}

qulonglong MainController::packetCount() const noexcept {
    return static_cast<qulonglong>(whole_capture_packet_count_);
}
qulonglong MainController::flowCount() const noexcept {
    return static_cast<qulonglong>(session_.summary().flow_count);
}

qulonglong MainController::capturedBytes() const noexcept {
    return static_cast<qulonglong>(whole_capture_captured_bytes_);
}

QString MainController::capturedBytesText() const {
    return QString::fromStdString(session_detail::format_statistics_compact_size_value(capturedBytes()));
}

qulonglong MainController::originalBytes() const noexcept {
    return static_cast<qulonglong>(whole_capture_original_bytes_);
}

QString MainController::originalBytesText() const {
    return QString::fromStdString(session_detail::format_statistics_compact_size_value(originalBytes()));
}

qulonglong MainController::totalBytes() const noexcept {
    return static_cast<qulonglong>(session_.summary().total_bytes);
}

QVariantMap MainController::captureTimeStatistics() const {
    return capture_time_statistics_;
}

QVariantMap MainController::captureMetrics() const {
    return capture_metrics_;
}

QVariantMap MainController::flowCharacteristics() const {
    return flow_characteristics_;
}

QVariantMap MainController::packetDirectionDistribution() const {
    return packet_direction_distribution_;
}

QVariantMap MainController::dataDirectionDistribution() const {
    return data_direction_distribution_;
}

QString MainController::statisticsPartialOpenWarningText() const {
    return statistics_partial_open_warning_text_;
}

int MainController::statisticsSectionsResetToken() const noexcept {
    return statistics_sections_reset_token_;
}

int MainController::packetSizeDistributionState() const noexcept {
    return static_cast<int>(packet_size_distribution_state_);
}

QString MainController::packetSizeDistributionStatusText() const {
    return statisticsSectionStatusText(StatisticsOptionalSection::packet_size_distribution);
}

QString MainController::packetSizeDistributionSummaryText() const {
    return packet_size_distribution_state_ == StatisticsSectionRequestState::ready
        ? QStringLiteral("%1 packets").arg(packet_size_statistics_.total_packet_count)
        : QString {};
}

qulonglong MainController::packetSizeDistributionTotalPacketCount() const noexcept {
    return static_cast<qulonglong>(packet_size_statistics_.total_packet_count);
}

qulonglong MainController::packetSizeDistributionMaximumBucketPacketCount() const noexcept {
    return static_cast<qulonglong>(packet_size_statistics_.maximum_bucket_packet_count);
}

qulonglong MainController::packetSizeDistributionMaximumCapturedPacketLength() const noexcept {
    return static_cast<qulonglong>(packet_size_statistics_.maximum_captured_packet_length);
}

QString MainController::packetSizeDistributionMaximumCapturedPacketLengthText() const {
    return QString::fromStdString(
        session_detail::format_statistics_size_value(packet_size_statistics_.maximum_captured_packet_length)
    );
}

QVariantList MainController::packetSizeDistributionRows() const {
    return packet_size_distribution_rows_;
}

int MainController::flowPacketHistogramState() const noexcept {
    return static_cast<int>(flow_packet_histogram_state_);
}

QString MainController::flowPacketHistogramStatusText() const {
    return statisticsSectionStatusText(StatisticsOptionalSection::flow_packet_histogram);
}

QString MainController::flowPacketHistogramSummaryText() const {
    return flow_packet_count_histogram_.total_flow_count > 0U
        ? QStringLiteral("%1 flows").arg(flow_packet_count_histogram_.total_flow_count)
        : QString {};
}

qulonglong MainController::flowPacketHistogramTotalFlowCount() const noexcept {
    return static_cast<qulonglong>(flow_packet_count_histogram_.total_flow_count);
}

qulonglong MainController::flowPacketHistogramMaximumBucketFlowCount() const noexcept {
    return static_cast<qulonglong>(flow_packet_count_histogram_.maximum_bucket_flow_count);
}

qulonglong MainController::flowPacketHistogramExcludedZeroPacketFlowCount() const noexcept {
    return static_cast<qulonglong>(flow_packet_count_histogram_.excluded_zero_packet_flow_count);
}

QVariantList MainController::flowPacketHistogramRows() const {
    return flow_packet_histogram_rows_;
}

int MainController::protocolHintsSectionState() const noexcept {
    return static_cast<int>(protocol_hints_section_state_);
}

QString MainController::protocolHintsSectionStatusText() const {
    return statisticsSectionStatusText(StatisticsOptionalSection::protocol_hints);
}

QVariantList MainController::protocolHintDistribution() const {
    return protocol_hint_distribution_;
}

int MainController::protocolPathSectionState() const noexcept {
    return static_cast<int>(protocol_path_section_state_);
}

QString MainController::protocolPathSectionStatusText() const {
    return statisticsSectionStatusText(StatisticsOptionalSection::protocol_path);
}

QVariantList MainController::protocolPathStatistics() const {
    QVariantList rows {};
    rows.reserve(static_cast<qsizetype>(protocol_path_summary_.rows.size()));

    for (const auto& row : protocol_path_summary_.rows) {
        QVariantMap item {};
        item.insert(QStringLiteral("nodeId"), static_cast<qulonglong>(row.node_id));
        item.insert(QStringLiteral("parentNodeId"), static_cast<qulonglong>(row.parent_node_id));
        item.insert(QStringLiteral("depth"), static_cast<qulonglong>(row.depth));
        item.insert(QStringLiteral("layerText"), QString::fromStdString(row.layer_text));
        item.insert(QStringLiteral("pathText"), QString::fromStdString(row.path_text));
        item.insert(QStringLiteral("compactText"), QString::fromStdString(row.compact_text));
        item.insert(QStringLiteral("hasChildren"), row.has_children);
        item.insert(QStringLiteral("isTerminal"), row.is_terminal);
        item.insert(QStringLiteral("flowCount"), static_cast<qulonglong>(row.flow_count));
        item.insert(QStringLiteral("packetCount"), static_cast<qulonglong>(row.packet_count));
        item.insert(QStringLiteral("originalByteCount"), static_cast<qulonglong>(row.original_byte_count));
        item.insert(QStringLiteral("flowPercent"), row.flow_percent);
        item.insert(QStringLiteral("packetPercent"), row.packet_percent);
        item.insert(QStringLiteral("originalBytePercent"), row.original_byte_percent);
        item.insert(QStringLiteral("flowCountText"), QString::fromStdString(row.flow_count_text));
        item.insert(QStringLiteral("packetCountText"), QString::fromStdString(row.packet_count_text));
        item.insert(QStringLiteral("originalByteCountText"), QString::fromStdString(row.original_byte_count_text));
        rows.push_back(item);
    }

    return rows;
}

QObject* MainController::protocolPathStatsModel() noexcept {
    return &protocol_path_stats_model_;
}

qulonglong MainController::tcpFlowCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.tcp.flow_count);
}

qulonglong MainController::tcpPacketCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.tcp.packet_count);
}

qulonglong MainController::tcpCapturedBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.tcp.captured_bytes);
}

QString MainController::tcpCapturedBytesText() const {
    return QString::fromStdString(session_detail::format_statistics_compact_size_value(tcpCapturedBytes()));
}

qulonglong MainController::tcpOriginalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.tcp.original_bytes);
}

QString MainController::tcpOriginalBytesText() const {
    return QString::fromStdString(session_detail::format_statistics_compact_size_value(tcpOriginalBytes()));
}

qulonglong MainController::tcpTotalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.tcp.original_bytes);
}

qulonglong MainController::udpFlowCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.udp.flow_count);
}

qulonglong MainController::udpPacketCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.udp.packet_count);
}

qulonglong MainController::udpCapturedBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.udp.captured_bytes);
}

QString MainController::udpCapturedBytesText() const {
    return QString::fromStdString(session_detail::format_statistics_compact_size_value(udpCapturedBytes()));
}

qulonglong MainController::udpOriginalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.udp.original_bytes);
}

QString MainController::udpOriginalBytesText() const {
    return QString::fromStdString(session_detail::format_statistics_compact_size_value(udpOriginalBytes()));
}

qulonglong MainController::udpTotalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.udp.original_bytes);
}

qulonglong MainController::sctpFlowCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.sctp.flow_count);
}

qulonglong MainController::sctpPacketCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.sctp.packet_count);
}

qulonglong MainController::sctpCapturedBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.sctp.captured_bytes);
}

QString MainController::sctpCapturedBytesText() const {
    return QString::fromStdString(session_detail::format_statistics_compact_size_value(sctpCapturedBytes()));
}

qulonglong MainController::sctpOriginalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.sctp.original_bytes);
}

QString MainController::sctpOriginalBytesText() const {
    return QString::fromStdString(session_detail::format_statistics_compact_size_value(sctpOriginalBytes()));
}

qulonglong MainController::sctpTotalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.sctp.original_bytes);
}

qulonglong MainController::otherFlowCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.other.flow_count);
}

qulonglong MainController::otherPacketCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.other.packet_count);
}

qulonglong MainController::otherCapturedBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.other.captured_bytes);
}

QString MainController::otherCapturedBytesText() const {
    return QString::fromStdString(session_detail::format_statistics_compact_size_value(otherCapturedBytes()));
}

qulonglong MainController::otherOriginalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.other.original_bytes);
}

QString MainController::otherOriginalBytesText() const {
    return QString::fromStdString(session_detail::format_statistics_compact_size_value(otherOriginalBytes()));
}

qulonglong MainController::otherTotalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.other.original_bytes);
}

qulonglong MainController::ipv4FlowCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.ipv4.flow_count);
}

qulonglong MainController::ipv4PacketCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.ipv4.packet_count);
}

qulonglong MainController::ipv4CapturedBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.ipv4.captured_bytes);
}

QString MainController::ipv4CapturedBytesText() const {
    return QString::fromStdString(session_detail::format_statistics_compact_size_value(ipv4CapturedBytes()));
}

qulonglong MainController::ipv4OriginalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.ipv4.original_bytes);
}

QString MainController::ipv4OriginalBytesText() const {
    return QString::fromStdString(session_detail::format_statistics_compact_size_value(ipv4OriginalBytes()));
}

qulonglong MainController::ipv4TotalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.ipv4.original_bytes);
}

qulonglong MainController::ipv6FlowCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.ipv6.flow_count);
}

qulonglong MainController::ipv6PacketCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.ipv6.packet_count);
}

qulonglong MainController::ipv6CapturedBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.ipv6.captured_bytes);
}

QString MainController::ipv6CapturedBytesText() const {
    return QString::fromStdString(session_detail::format_statistics_compact_size_value(ipv6CapturedBytes()));
}

qulonglong MainController::ipv6OriginalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.ipv6.original_bytes);
}

QString MainController::ipv6OriginalBytesText() const {
    return QString::fromStdString(session_detail::format_statistics_compact_size_value(ipv6OriginalBytes()));
}

qulonglong MainController::ipv6TotalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.ipv6.original_bytes);
}

qulonglong MainController::unrecognizedStatsPacketCount() const noexcept {
    return static_cast<qulonglong>(unrecognized_packet_statistics_.packet_count);
}

qulonglong MainController::unrecognizedStatsCapturedBytes() const noexcept {
    return static_cast<qulonglong>(unrecognized_packet_statistics_.captured_bytes);
}

qulonglong MainController::unrecognizedStatsOriginalBytes() const noexcept {
    return static_cast<qulonglong>(unrecognized_packet_statistics_.original_bytes);
}

int MainController::quicTlsSectionState() const noexcept {
    return static_cast<int>(quic_tls_section_state_);
}

QString MainController::quicTlsSectionStatusText() const {
    return statisticsSectionStatusText(StatisticsOptionalSection::quic_tls);
}

qulonglong MainController::quicTotalFlows() const noexcept {
    return static_cast<qulonglong>(quic_recognition_stats_.total_flows);
}

qulonglong MainController::quicWithSni() const noexcept {
    return static_cast<qulonglong>(quic_recognition_stats_.with_sni);
}

qulonglong MainController::quicWithoutSni() const noexcept {
    return static_cast<qulonglong>(quic_recognition_stats_.without_sni);
}

qulonglong MainController::quicVersionV1() const noexcept {
    return static_cast<qulonglong>(quic_recognition_stats_.version_v1);
}

qulonglong MainController::quicVersionDraft29() const noexcept {
    return static_cast<qulonglong>(quic_recognition_stats_.version_draft29);
}

qulonglong MainController::quicVersionV2() const noexcept {
    return static_cast<qulonglong>(quic_recognition_stats_.version_v2);
}

qulonglong MainController::quicVersionUnknown() const noexcept {
    return static_cast<qulonglong>(quic_recognition_stats_.version_unknown);
}

qulonglong MainController::tlsTotalFlows() const noexcept {
    return static_cast<qulonglong>(tls_recognition_stats_.total_flows);
}

qulonglong MainController::tlsWithSni() const noexcept {
    return static_cast<qulonglong>(tls_recognition_stats_.with_sni);
}

qulonglong MainController::tlsWithoutSni() const noexcept {
    return static_cast<qulonglong>(tls_recognition_stats_.without_sni);
}

qulonglong MainController::tlsVersion12() const noexcept {
    return static_cast<qulonglong>(tls_recognition_stats_.version_tls12);
}

qulonglong MainController::tlsVersion13() const noexcept {
    return static_cast<qulonglong>(tls_recognition_stats_.version_tls13);
}

qulonglong MainController::tlsVersionUnknown() const noexcept {
    return static_cast<qulonglong>(tls_recognition_stats_.version_unknown);
}

int MainController::topEndpointPortSectionState() const noexcept {
    return static_cast<int>(top_endpoints_ports_section_state_);
}

QString MainController::topEndpointPortSectionStatusText() const {
    return statisticsSectionStatusText(StatisticsOptionalSection::top_endpoints_ports);
}

int MainController::statisticsMode() const noexcept {
    return statistics_mode_;
}

bool MainController::httpUsePathAsServiceHint() const noexcept {
    return pending_analysis_settings_.http_use_path_as_service_hint;
}

bool MainController::usePossibleTlsQuic() const noexcept {
    return pending_analysis_settings_.use_possible_tls_quic;
}

bool MainController::ignoreVlanAndMplsLayersWhenGroupingFlows() const noexcept {
    return pending_analysis_settings_.ignore_vlan_and_mpls_layers_when_grouping_flows;
}

bool MainController::ignoreGtpuTeidsWhenGroupingInnerFlows() const noexcept {
    return pending_analysis_settings_.ignore_gtpu_teids_when_grouping_inner_flows;
}

bool MainController::validateSelectedPacketChecksums() const noexcept {
    return validate_selected_packet_checksums_;
}

bool MainController::showWiresharkFilterForSelectedFlow() const noexcept {
    return show_wireshark_filter_for_selected_flow_;
}

bool MainController::showProtocolPathColumn() const noexcept {
    return show_protocol_path_column_;
}

bool MainController::showFragmentedPacketCountColumn() const noexcept {
    return show_fragmented_packet_count_column_;
}

bool MainController::developerDiagnosticsAvailable() const noexcept {
#ifndef NDEBUG
    return true;
#else
    return false;
#endif
}

QString MainController::flowGroupingWarningText() const {
    if (!session_.has_capture()) {
        return {};
    }

    return session_.flow_grouping_ignores_vlan_and_mpls_layers()
        ? QStringLiteral("VLAN and MPLS layers are ignored for flow grouping. Flows from different VLANs or MPLS paths may be merged.")
        : QString {};
}

QString MainController::gtpuTeidGroupingInfoText() const {
    if (!session_.has_capture()) {
        return {};
    }

    return session_.flow_grouping_ignores_gtpu_teids()
        ? QStringLiteral("GTP-U TEIDs are ignored for inner-flow grouping. Flows from different GTP-U tunnels may be merged.")
        : QString {};
}

QString MainController::selectedFlowWiresharkFilter() const {
    if (!show_wireshark_filter_for_selected_flow_) {
        return {};
    }

    return selected_flow_wireshark_filter(flow_model_, selected_flow_index_);
}

QVariantList MainController::protocolPathLegend() const {
    return protocol_path_legend_to_variant_list();
}

QVariantList MainController::supportedProtocolCatalog() const {
    return supported_protocol_catalog_to_variant_list();
}

QVariantList MainController::byteExportFormats() const {
    QVariantList formats {};
    for (const auto& descriptor : session_detail::byte_export_format_descriptors()) {
        QVariantMap item {};
        item.insert(QStringLiteral("stableId"), QString::fromStdString(descriptor.stable_id));
        item.insert(QStringLiteral("label"), QString::fromStdString(descriptor.label));
        item.insert(QStringLiteral("suggestedExtension"), QString::fromStdString(descriptor.suggested_extension));
        item.insert(QStringLiteral("binaryOutput"), descriptor.binary_output);
        formats.push_back(item);
    }
    return formats;
}

bool MainController::selectedFlowHasWiresharkFilter() const {
    return !selectedFlowWiresharkFilter().isEmpty();
}

bool MainController::selectedFlowUsesTcp() const {
    return !unrecognized_packets_selected_ && selected_flow_uses_tcp(flow_model_, selected_flow_index_);
}

bool MainController::hasProtocolPathFlowFilter() const noexcept {
    return has_active_protocol_path_filter_;
}

QString MainController::protocolPathFlowFilterText() const {
    return active_protocol_path_filter_label_;
}

int MainController::currentTabIndex() const noexcept {
    return current_tab_index_;
}

QObject* MainController::topEndpointsModel() noexcept {
    return &top_endpoints_model_;
}

QObject* MainController::topPortsModel() noexcept {
    return &top_ports_model_;
}

QObject* MainController::flowModel() noexcept {
    return &flow_model_;
}

QObject* MainController::packetModel() noexcept {
    return &packet_model_;
}

QObject* MainController::streamModel() noexcept {
    return &stream_model_;
}

QObject* MainController::packetDetailsModel() noexcept {
    return &packet_details_model_;
}

int MainController::selectedFlowIndex() const noexcept {
    return selected_flow_index_;
}

bool MainController::unrecognizedPacketsSelected() const noexcept {
    return unrecognized_packets_selected_;
}

qulonglong MainController::unrecognizedPacketCount() const noexcept {
    return static_cast<qulonglong>(session_.unrecognized_packet_count());
}

qulonglong MainController::selectedPacketIndex() const noexcept {
    return selected_packet_index_;
}

qulonglong MainController::selectedStreamItemIndex() const noexcept {
    return selected_stream_item_index_;
}

int MainController::flowFilterMode() const noexcept {
    return static_cast<int>(flow_filter_mode_);
}

QString MainController::flowFilterText() const {
    return simple_flow_filter_text_;
}

bool MainController::smartExportCurrentFilterAvailable() const noexcept {
    if (flow_filter_mode_ == FlowFilterMode::simple) {
        return !simple_flow_filter_text_.trimmed().isEmpty();
    }
    if (flow_filter_mode_ == FlowFilterMode::advanced) {
        return advanced_flow_filter_document_state_.active_rule_count() > 0U;
    }
    return false;
}

QString MainController::advancedFlowFilterDisplayName() const {
    const auto* source_path = advanced_flow_filter_document_state_.source_path();
    if (source_path == nullptr) {
        return QStringLiteral("Custom filter");
    }

    QString display_name = advanced_filter_source_stem_text(*source_path);
    if (advanced_flow_filter_document_state_.has_unsaved_changes() ||
        advanced_flow_filter_editor_model_.hasUnsynchronizedBufferedChanges()) {
        display_name += QStringLiteral(" *");
    }
    return display_name;
}

QString MainController::advancedFlowFilterRuleCountText() const {
    return format_rule_count_text(advanced_flow_filter_document_state_.active_rule_count());
}

bool MainController::advancedFlowFilterSettingsAvailable() const noexcept {
    return true;
}

bool MainController::advancedFlowFilterClearAvailable() const noexcept {
    return advanced_flow_filter_editor_model_.hasUnsynchronizedBufferedChanges() ||
        !is_default_advanced_flow_filter_document(
            advanced_flow_filter_document_state_.current_user_visible_document());
}

int MainController::advancedFlowFilterEditorRevision() const noexcept {
    return advanced_flow_filter_editor_model_.revision();
}

QString MainController::advancedFlowFilterEditorValidationText() const {
    return advanced_flow_filter_editor_model_.validationText();
}

QObject* MainController::advancedFlowFilterEditor() noexcept {
    return &advanced_flow_filter_editor_model_;
}

QObject* MainController::advancedFlowFilterProtocolPathSelector() noexcept {
    return &advanced_flow_filter_protocol_path_selector_model_;
}

bool MainController::advancedFlowFilterDraftClearAllAvailable() const noexcept {
    return advanced_flow_filter_editor_model_.draftClearAllAvailable();
}

bool MainController::advancedFlowFilterSectionEnabled(const int section) const noexcept {
    return advanced_flow_filter_editor_model_.sectionEnabled(section);
}

bool MainController::advancedFlowFilterSectionHasExclusions(const int section) const noexcept {
    return advanced_flow_filter_editor_model_.sectionHasExclusions(section);
}

QVariantList MainController::advancedFlowFilterIncludeOptions(const int section) const {
    return advanced_flow_filter_editor_model_.includeOptions(section);
}

QVariantList MainController::advancedFlowFilterExcludeOptions(const int section) const {
    return advanced_flow_filter_editor_model_.excludeOptions(section);
}

QVariantList MainController::advancedFlowFilterPortScopeOptions() const {
    return advanced_flow_filter_editor_model_.portScopeOptions();
}

QVariantList MainController::advancedFlowFilterAddressScopeOptions() const {
    return advanced_flow_filter_editor_model_.addressScopeOptions();
}

QVariantList MainController::advancedFlowFilterPortRows(const bool exclude) const {
    return advanced_flow_filter_editor_model_.portRows(exclude);
}

QVariantList MainController::advancedFlowFilterAddressRows(const bool exclude) const {
    return advanced_flow_filter_editor_model_.addressRows(exclude);
}

QVariantList MainController::advancedFlowFilterProtocolPathRows(const bool exclude) const {
    return advanced_flow_filter_editor_model_.protocolPathRows(exclude);
}

int MainController::flowSortColumn() const noexcept {
    return column_from_sort_key(flow_model_.sortKey());
}

bool MainController::flowSortAscending() const noexcept {
    return flow_model_.sortAscending();
}

bool MainController::openCaptureFile(const QString& path) {
    if (flow_info_csv_export_in_progress_) {
        setStatusText(QStringLiteral("Wait for the current flow info CSV export to finish before opening another capture."), true);
        return false;
    }
    if (smart_export_in_progress_) {
        setStatusText(QStringLiteral("Wait for the current smart export to finish before opening another capture."), true);
        return false;
    }
    if (index_save_in_progress_) {
        setStatusText(QStringLiteral("Wait for the current index save to finish before opening another capture."), true);
        return false;
    }
    return openPath(path, false);
}

bool MainController::openIndexFile(const QString& path) {
    if (flow_info_csv_export_in_progress_) {
        setStatusText(QStringLiteral("Wait for the current flow info CSV export to finish before opening another session."), true);
        return false;
    }
    if (smart_export_in_progress_) {
        setStatusText(QStringLiteral("Wait for the current smart export to finish before opening another session."), true);
        return false;
    }
    if (index_save_in_progress_) {
        setStatusText(QStringLiteral("Wait for the current index save to finish before opening another session."), true);
        return false;
    }
    return openPath(path, true);
}

bool MainController::attachSourceCapture(const QString& path) {
    if (flow_info_csv_export_in_progress_) {
        setStatusText(QStringLiteral("Wait for the current flow info CSV export to finish before changing the source capture."), true);
        return false;
    }
    if (smart_export_in_progress_) {
        setStatusText(QStringLiteral("Wait for the current smart export to finish before changing the source capture."), true);
        return false;
    }
    if (index_save_in_progress_) {
        setStatusText(QStringLiteral("Wait for the current index save to finish before changing the source capture."), true);
        return false;
    }

    const QString trimmedPath = path.trimmed();
    if (trimmedPath.isEmpty()) {
        setStatusText(QStringLiteral("No source capture selected."), true);
        return false;
    }

    if (!canAttachSourceCapture()) {
        setStatusText(QStringLiteral("Source capture attachment is not available for the current session."), true);
        return false;
    }

    const auto filesystemPath = std::filesystem::path {trimmedPath.toStdWString()};
    if (!session_.attach_source_capture(filesystemPath)) {
        setStatusText(QStringLiteral("Selected file does not match the expected source capture."), true);
        return false;
    }

    setLastDirectoryFromPath(filesystemPath);
    source_capture_unavailable_notice_shown_ = false;
    if (selected_flow_index_ >= 0) {
        current_stream_items_.clear();
        stream_model_.clear();
        stream_loading_ = false;
        loaded_stream_item_count_ = 0U;
        total_stream_item_count_ = 0U;
        stream_packet_window_count_ = 0U;
        stream_item_budget_count_ = 0U;
    can_load_more_stream_items_ = false;
    stream_state_materialized_for_selected_flow_ = false;
        if (stream_tab_active_) {
            refreshSelectedStreamItems(true);
        } else {
            emit streamListStateChanged();
        }
    }
    reloadActiveDetails();
    emit stateChanged();
    emit sourceAvailabilityChanged();
    emit actionAvailabilityChanged();
    setStatusText(QStringLiteral("Source capture attached successfully."));
    return true;
}

void MainController::cancelOpen() {
    if (active_open_context_ == nullptr || !is_opening_) {
        return;
    }

    active_open_context_->request_cancel();
    setStatusText(QStringLiteral("Cancelling open operation..."));
}


void MainController::loadMorePackets() {
    if (!canLoadMorePackets()) {
        return;
    }

    if (unrecognized_packets_selected_) {
        refreshUnrecognizedPackets(false);
        return;
    }

    refreshSelectedFlowPackets(false);
}


void MainController::loadMoreStreamItems() {
    if (!canLoadMoreStreamItems()) {
        return;
    }

    refreshSelectedStreamItems(false);
}

void MainController::sendSelectedFlowToAnalysis() {
    if (selected_flow_index_ < 0) {
        return;
    }

    setCurrentTabIndex(kAnalysisTabIndex);
    refreshSelectedFlowAnalysis();
}

void MainController::cancelSaveAnalysisIndex() {
    if (!index_save_in_progress_ || index_save_cancel_requested_) {
        return;
    }

    if (index_save_cancel_token_ != nullptr) {
        index_save_cancel_token_->store(true, std::memory_order_relaxed);
    }

    const auto cancelling_text = index_save_progress_text_.isEmpty()
        ? QStringLiteral("Cancelling index save...")
        : index_save_progress_text_ + QStringLiteral(" Cancelling...");
    setIndexSaveState(true, true, index_save_progress_percent_, cancelling_text);
    setStatusText(QStringLiteral("Cancelling index save..."));
}

bool MainController::saveAnalysisIndex(const QString& path) {
    if (flow_info_csv_export_in_progress_ || flow_info_csv_export_thread_ != nullptr) {
        setStatusText(QStringLiteral("Wait for the current flow info CSV export to finish before saving an analysis index."), true);
        return false;
    }

    if (smart_export_in_progress_ || smart_export_thread_ != nullptr) {
        setStatusText(QStringLiteral("Wait for the current smart export to finish before saving an analysis index."), true);
        return false;
    }

    if (analysis_sequence_export_in_progress_ || analysis_sequence_export_thread_ != nullptr) {
        setStatusText(QStringLiteral("Wait for the current analysis sequence export to finish before saving an analysis index."), true);
        return false;
    }

    if (is_opening_) {
        setStatusText(QStringLiteral("Wait for the current open operation to finish before saving an analysis index."), true);
        return false;
    }

    if (index_save_in_progress_ || index_save_thread_ != nullptr) {
        setStatusText(QStringLiteral("An analysis index save is already in progress."), true);
        return false;
    }

    const QString trimmedPath = path.trimmed();
    if (trimmedPath.isEmpty()) {
        setStatusText(QStringLiteral("No output file selected."), true);
        return false;
    }

    if (!ensureSourceCaptureAvailable(QStringLiteral("Original source capture is unavailable. Reattach the capture file to save an analysis index."))) {
        return false;
    }

    const auto filesystemPath = std::filesystem::path {trimmedPath.toStdWString()};
    setLastDirectoryFromPath(filesystemPath);

    ++active_index_save_job_id_;
    const auto job_id = active_index_save_job_id_;
    index_save_cancel_token_ = std::make_shared<std::atomic_bool>(false);
    index_save_cancel_requested_ = false;
    setIndexSaveState(true, false, 0.0, QStringLiteral("Preparing index save..."));
    setStatusText(QStringLiteral("Analysis index save started."));

    const IndexSaveOptions options {
        .progress_callback = [this, job_id](const IndexSaveProgress& progress) {
            QMetaObject::invokeMethod(
                this,
                [this, job_id, progress]() {
                    updateIndexSaveProgress(job_id, progress);
                },
                Qt::QueuedConnection
            );
        },
        .cancel_requested = [token = index_save_cancel_token_]() {
            return token != nullptr && token->load(std::memory_order_relaxed);
        },
    };

    index_save_thread_ = QThread::create([this, job_id, trimmedPath, filesystemPath, options]() mutable {
        std::string error_text {};
        const bool saved = session_.save_index(filesystemPath, options, &error_text);
        QMetaObject::invokeMethod(this, [this, job_id, trimmedPath, saved, error = QString::fromStdString(error_text)]() {
            completeIndexSave(job_id, trimmedPath, saved, error);
        }, Qt::QueuedConnection);
    });

    QObject::connect(index_save_thread_, &QThread::finished, index_save_thread_, &QObject::deleteLater);
    index_save_thread_->start();
    return true;
}

bool MainController::exportFlows(
    const QString& path,
    const std::vector<int>& flowIndices,
    const QString& emptySelectionMessage,
    const QString& failureMessage,
    const QString& successMessage
) {
    if (flow_info_csv_export_in_progress_ || flow_info_csv_export_thread_ != nullptr) {
        setStatusText(QStringLiteral("Wait for the current flow info CSV export to finish before exporting flows."), true);
        return false;
    }

    if (flowIndices.empty()) {
        setStatusText(emptySelectionMessage, true);
        return false;
    }

    if (!ensureSourceCaptureAvailable(QStringLiteral("Original source capture is unavailable. Reattach the capture file to export flows."))) {
        return false;
    }

    const QString trimmedPath = path.trimmed();
    if (trimmedPath.isEmpty()) {
        setStatusText(QStringLiteral("No output file selected."), true);
        return false;
    }

    std::vector<std::size_t> exportIndices {};
    exportIndices.reserve(flowIndices.size());
    for (const auto flowIndex : flowIndices) {
        if (flowIndex < 0) {
            setStatusText(failureMessage, true);
            return false;
        }
        exportIndices.push_back(static_cast<std::size_t>(flowIndex));
    }

    const auto filesystemPath = std::filesystem::path {trimmedPath.toStdWString()};
    const bool exported = session_.export_flows_to_pcap(exportIndices, filesystemPath);
    if (!exported) {
        setStatusText(failureMessage, true);
        return false;
    }

    setLastDirectoryFromPath(filesystemPath);
    setStatusText(successMessage);
    return true;
}

bool MainController::exportSelectedFlow(const QString& path) {
    if (selected_flow_index_ < 0) {
        setStatusText(QStringLiteral("No flow selected for export."), true);
        return false;
    }

    return exportFlows(
        path,
        {selected_flow_index_},
        QStringLiteral("No flow selected for export."),
        QStringLiteral("Failed to export selected flow."),
        QStringLiteral("Flow exported successfully.")
    );
}

bool MainController::exportSelectedFlowSequenceCsv(const QString& path) {
    if (selected_flow_index_ < 0) {
        setAnalysisSequenceExportState(false, QStringLiteral("No flow selected for sequence export."), true);
        return false;
    }

    if (flow_info_csv_export_in_progress_ || flow_info_csv_export_thread_ != nullptr) {
        setAnalysisSequenceExportState(false, QStringLiteral("Wait for the current flow info CSV export to finish before exporting flow sequence."), true);
        return false;
    }

    if (analysis_sequence_export_in_progress_ || analysis_sequence_export_thread_ != nullptr) {
        setAnalysisSequenceExportState(true, QStringLiteral("Exporting flow sequence..."), false);
        return false;
    }

    const QString trimmedPath = path.trimmed();
    if (trimmedPath.isEmpty()) {
        setAnalysisSequenceExportState(false, QStringLiteral("No output file selected."), true);
        return false;
    }

    setAnalysisSequenceExportState(true, QStringLiteral("Exporting flow sequence..."), false);

    const auto flow_index = static_cast<std::size_t>(selected_flow_index_);
    const auto rows = build_analysis_sequence_export_rows(session_, flow_index, selected_flow_protocol_hint(flow_model_, selected_flow_index_));
    if (!rows.has_value()) {
        setAnalysisSequenceExportState(false, QStringLiteral("Failed to prepare flow sequence export."), true);
        return false;
    }

    const auto filesystemPath = std::filesystem::path {trimmedPath.toStdWString()};
    setLastDirectoryFromPath(filesystemPath);

    ++active_analysis_sequence_export_job_id_;
    const auto job_id = active_analysis_sequence_export_job_id_;
    analysis_sequence_export_thread_ = QThread::create([this, job_id, trimmedPath, filesystemPath, rows = std::move(*rows)]() mutable {
        QString error_text {};
        const bool exported = write_analysis_sequence_csv(rows, filesystemPath, &error_text);
        QMetaObject::invokeMethod(this, [this, job_id, trimmedPath, exported, error_text]() {
            completeAnalysisSequenceExport(job_id, trimmedPath, exported, error_text);
        }, Qt::QueuedConnection);
    });

    QObject::connect(analysis_sequence_export_thread_, &QThread::finished, analysis_sequence_export_thread_, &QObject::deleteLater);
    analysis_sequence_export_thread_->start();
    return true;
}

void MainController::clearSelectedFlows() {
    flow_model_.clearCheckedFlows();
}

bool MainController::exportSelectedFlows(const QString& path) {
    return exportFlows(
        path,
        flow_model_.checkedFlowIndices(),
        QStringLiteral("No selected flows for export."),
        QStringLiteral("Failed to export selected flows."),
        QStringLiteral("Selected flows exported successfully.")
    );
}

bool MainController::exportUnselectedFlows(const QString& path) {
    return exportFlows(
        path,
        flow_model_.uncheckedFlowIndices(),
        QStringLiteral("No unselected flows for export."),
        QStringLiteral("Failed to export unselected flows."),
        QStringLiteral("Unselected flows exported successfully.")
    );
}

bool MainController::exportAllFlowsInfoCsv(const QString& path) {
    if (is_opening_) {
        setStatusText(QStringLiteral("Wait for the current open operation to finish before exporting flow info CSV."), true);
        return false;
    }

    if (smart_export_in_progress_ || smart_export_thread_ != nullptr) {
        setStatusText(QStringLiteral("Wait for the current smart export to finish before exporting flow info CSV."), true);
        return false;
    }

    if (index_save_in_progress_ || index_save_thread_ != nullptr) {
        setStatusText(QStringLiteral("Wait for the current index save to finish before exporting flow info CSV."), true);
        return false;
    }

    if (flow_info_csv_export_in_progress_ || flow_info_csv_export_thread_ != nullptr) {
        setStatusText(QStringLiteral("Flow info CSV export is already in progress."), true);
        return false;
    }

    if (!hasCapture() || flow_model_.totalFlowCount() == 0) {
        setStatusText(QStringLiteral("No flows available for CSV export."), true);
        return false;
    }

    const QString trimmedPath = path.trimmed();
    if (trimmedPath.isEmpty()) {
        setStatusText(QStringLiteral("No output file selected."), true);
        return false;
    }

    const auto filesystemPath = std::filesystem::path {trimmedPath.toStdWString()};
    setLastDirectoryFromPath(filesystemPath);
    setStatusText(QStringLiteral("Exporting flow info CSV..."));
    flow_info_csv_export_in_progress_ = true;
    emit actionAvailabilityChanged();

    ++active_flow_info_csv_export_job_id_;
    const auto job_id = active_flow_info_csv_export_job_id_;
    flow_info_csv_export_thread_ = QThread::create([this, job_id, trimmedPath, filesystemPath]() mutable {
        std::string error_text {};
        const bool exported = session_.export_all_flows_info_csv(filesystemPath, &error_text);
        QMetaObject::invokeMethod(this, [this, job_id, trimmedPath, exported, error_text = QString::fromStdString(error_text)]() {
            completeFlowInfoCsvExport(job_id, trimmedPath, exported, error_text);
        }, Qt::QueuedConnection);
    });

    QObject::connect(flow_info_csv_export_thread_, &QThread::finished, flow_info_csv_export_thread_, &QObject::deleteLater);
    flow_info_csv_export_thread_->start();
    return true;
}

bool MainController::exportProtocolPathTree(const QString& path) {
    if (is_opening_) {
        setStatusText(QStringLiteral("Wait for the current open operation to finish before exporting Protocol Path Tree."), true);
        return false;
    }

    if (smart_export_in_progress_ || smart_export_thread_ != nullptr) {
        setStatusText(QStringLiteral("Wait for the current smart export to finish before exporting Protocol Path Tree."), true);
        return false;
    }

    if (index_save_in_progress_ || index_save_thread_ != nullptr) {
        setStatusText(QStringLiteral("Wait for the current index save to finish before exporting Protocol Path Tree."), true);
        return false;
    }

    if (!hasCapture()) {
        setStatusText(QStringLiteral("No capture is open."), true);
        return false;
    }

    const QString trimmedPath = path.trimmed();
    if (trimmedPath.isEmpty()) {
        setStatusText(QStringLiteral("No output file selected."), true);
        return false;
    }

    const auto filesystemPath = std::filesystem::path {trimmedPath.toStdWString()};
    setLastDirectoryFromPath(filesystemPath);

    std::string error_text {};
    if (!session_.export_protocol_path_tree_text(
            protocol_path_statistics_mode_from_int(statistics_mode_),
            filesystemPath,
            session_detail::TextExportOverwritePolicy::overwrite_existing,
            &error_text)) {
        setStatusText(
            error_text.empty()
                ? QStringLiteral("Failed to export Protocol Path Tree.")
                : QString::fromStdString(error_text),
            true
        );
        return false;
    }

    setStatusText(QStringLiteral("Protocol Path Tree exported successfully."));
    return true;
}

bool MainController::exportSmartFlows(
    const QString& path,
    const int outputMode,
    const int flowScopeMode,
    const int baseSelectionMode,
    const QString& packetCountText,
    const QString& originalBytesText,
    const QString& bufferBudgetPresetText,
    const bool includeLastPacket,
    const bool includeEveryKthPacket,
    const QString& everyKText
) {
    if (flow_info_csv_export_in_progress_ || flow_info_csv_export_thread_ != nullptr) {
        setStatusText(QStringLiteral("Wait for the current flow info CSV export to finish before starting smart export."), true);
        return false;
    }

    if (index_save_in_progress_) {
        setStatusText(QStringLiteral("Wait for the current index save to finish before starting smart export."), true);
        return false;
    }

    if (!ensureSourceCaptureAvailable(QStringLiteral("Original source capture is unavailable. Reattach the capture file to export flows."))) {
        return false;
    }

    if (smart_export_in_progress_ || smart_export_thread_ != nullptr) {
        setStatusText(QStringLiteral("A smart export is already in progress."), true);
        return false;
    }

    const QString trimmedPath = path.trimmed();
    if (trimmedPath.isEmpty()) {
        setStatusText(
            outputMode == kSmartExportOutputModeSeparateFilePerFlow
                ? QStringLiteral("No destination folder selected for smart export.")
                : QStringLiteral("No output file selected."),
            true
        );
        return false;
    }

    if (outputMode != kSmartExportOutputModeSingleFile && outputMode != kSmartExportOutputModeSeparateFilePerFlow) {
        setStatusText(QStringLiteral("Invalid smart export output mode."), true);
        return false;
    }

    SmartPacketRetentionOptions retention {};
    switch (baseSelectionMode) {
    case kSmartExportBaseModeAllPackets:
        retention.base_mode = SmartFlowExportBaseMode::all_packets;
        break;
    case kSmartExportBaseModeFirstNPackets: {
        const auto value = parse_positive_u64(packetCountText);
        if (!value.has_value()) {
            setStatusText(QStringLiteral("Enter a positive packet count for smart export."), true);
            return false;
        }
        retention.base_mode = SmartFlowExportBaseMode::first_n_packets;
        retention.first_n_packets = *value;
        break;
    }
    case kSmartExportBaseModeFirstMOriginalBytes: {
        const auto value = parse_positive_u64(originalBytesText);
        if (!value.has_value()) {
            setStatusText(QStringLiteral("Enter a positive original-byte limit for smart export."), true);
            return false;
        }
        retention.base_mode = SmartFlowExportBaseMode::first_m_original_bytes;
        retention.first_m_original_bytes = *value;
        break;
    }
    default:
        setStatusText(QStringLiteral("Invalid smart export base selection."), true);
        return false;
    }

    if (retention.base_mode != SmartFlowExportBaseMode::all_packets) {
        retention.include_last_packet = includeLastPacket;
        retention.include_every_kth_packet_after_base = includeEveryKthPacket;
        if (includeEveryKthPacket) {
            const auto value = parse_positive_u64(everyKText);
            if (!value.has_value()) {
                setStatusText(QStringLiteral("Enter a positive K value for sparse smart export retention."), true);
                return false;
            }
            retention.every_kth_packet = *value;
        }
    }

    std::vector<int> flow_indices {};
    QString empty_selection_message {};
    switch (flowScopeMode) {
    case kSmartExportFlowScopeCurrentFlow:
        flow_indices = (selected_flow_index_ >= 0) ? std::vector<int>{selected_flow_index_} : std::vector<int>{};
        empty_selection_message = QStringLiteral("No current flow selected for smart export.");
        break;
    case kSmartExportFlowScopeSelectedFlows:
        flow_indices = flow_model_.checkedFlowIndices();
        empty_selection_message = QStringLiteral("No selected flows for smart export.");
        break;
    case kSmartExportFlowScopeUnselectedFlows:
        flow_indices = flow_model_.uncheckedFlowIndices();
        empty_selection_message = QStringLiteral("No unselected flows for smart export.");
        break;
    case kSmartExportFlowScopeAllFlows: {
        const auto rows = session_.list_flows();
        flow_indices.reserve(rows.size());
        for (const auto& row : rows) {
            if (row.index > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
                setStatusText(QStringLiteral("Smart export flow index is out of range."), true);
                return false;
            }
            flow_indices.push_back(static_cast<int>(row.index));
        }
        empty_selection_message = QStringLiteral("No flows available for smart export.");
        break;
    }
    case kSmartExportFlowScopeMatchingCurrentFilter:
        if (!smartExportCurrentFilterAvailable()) {
            setStatusText(QStringLiteral("Current-filter smart export requires a non-empty Simple Filter or an Advanced Filter with at least one active rule."), true);
            return false;
        }
        flow_indices = smartExportCurrentFilterFlowIndices(true);
        empty_selection_message = QStringLiteral("No flows match the current filter for smart export.");
        break;
    case kSmartExportFlowScopeNotMatchingCurrentFilter:
        if (!smartExportCurrentFilterAvailable()) {
            setStatusText(QStringLiteral("Current-filter smart export requires a non-empty Simple Filter or an Advanced Filter with at least one active rule."), true);
            return false;
        }
        flow_indices = smartExportCurrentFilterFlowIndices(false);
        empty_selection_message = QStringLiteral("No flows remain outside the current filter for smart export.");
        break;
    case kSmartExportFlowScopeUnrecognizedPackets:
        if (outputMode == kSmartExportOutputModeSeparateFilePerFlow) {
            setStatusText(QStringLiteral("Unrecognized packets can only be smart-exported to a single output file."), true);
            return false;
        }
        if (session_.unrecognized_packet_count() == 0U) {
            setStatusText(QStringLiteral("No unrecognized packets available for smart export."), true);
            return false;
        }
        break;
    default:
        setStatusText(QStringLiteral("Invalid smart export flow selection."), true);
        return false;
    }

    if (flowScopeMode != kSmartExportFlowScopeUnrecognizedPackets && flow_indices.empty()) {
        setStatusText(empty_selection_message, true);
        return false;
    }

    const auto filesystemPath = std::filesystem::path {trimmedPath.toStdWString()};
    setLastDirectoryFromPath(filesystemPath);

    if (flowScopeMode == kSmartExportFlowScopeUnrecognizedPackets) {
        ++active_smart_export_job_id_;
        const auto job_id = active_smart_export_job_id_;
        smart_export_cancel_token_ = std::make_shared<std::atomic_bool>(false);
        smart_export_cancel_requested_ = false;

        const SmartSingleFileExportOptions export_options {
            .progress_callback = [this, job_id](const SmartSingleFileExportProgress& progress) {
                QMetaObject::invokeMethod(
                    this,
                    [this, job_id, progress]() {
                        updateSmartExportProgress(
                            job_id,
                            SmartPerFlowExportPhase::writing,
                            static_cast<qulonglong>(progress.packets_processed),
                            static_cast<qulonglong>(progress.total_packets_to_scan),
                            static_cast<qulonglong>(progress.exported_packets_written),
                            static_cast<qulonglong>(progress.total_selected_packets)
                        );
                    },
                    Qt::QueuedConnection
                );
            },
            .cancel_requested = [token = smart_export_cancel_token_]() {
                return token != nullptr && token->load(std::memory_order_relaxed);
            },
        };

        setSmartExportState(true, 0U, 0U, QStringLiteral("Starting smart export..."));
        setStatusText(QStringLiteral("Smart export started."));
        smart_export_thread_ = QThread::create([this, job_id, filesystemPath, retention, export_options]() mutable {
            std::string error_text {};
            const bool exported = session_.export_smart_unrecognized_packets_to_pcap(retention, filesystemPath, export_options, &error_text);
            const bool cancelled = error_text == "Smart export cancelled by user.";
            QMetaObject::invokeMethod(this, [this, job_id, exported, cancelled, error = QString::fromStdString(error_text)]() {
                completeSmartExport(
                    job_id,
                    QStringLiteral("Smart export completed successfully."),
                    QStringLiteral("Failed to smart-export unrecognized packets."),
                    exported,
                    cancelled,
                    error
                );
            }, Qt::QueuedConnection);
        });

        QObject::connect(smart_export_thread_, &QThread::finished, smart_export_thread_, &QObject::deleteLater);
        smart_export_thread_->start();
        return true;
    }

    SmartFlowExportRequest request {};
    request.flow_indices.reserve(flow_indices.size());
    for (const auto flow_index : flow_indices) {
        if (flow_index < 0) {
            setStatusText(QStringLiteral("Failed to prepare smart export flow list."), true);
            return false;
        }
        request.flow_indices.push_back(static_cast<std::size_t>(flow_index));
    }
    request.base_mode = retention.base_mode;
    request.first_n_packets = retention.first_n_packets;
    request.first_m_original_bytes = retention.first_m_original_bytes;
    request.include_last_packet = retention.include_last_packet;
    request.include_every_kth_packet_after_base = retention.include_every_kth_packet_after_base;
    request.every_kth_packet = retention.every_kth_packet;

    if (outputMode == kSmartExportOutputModeSeparateFilePerFlow) {
        const auto buffer_budget_mb = parse_positive_u64(bufferBudgetPresetText);
        if (!buffer_budget_mb.has_value()) {
            setStatusText(QStringLiteral("Select a valid buffer memory budget preset for per-flow smart export."), true);
            return false;
        }
        if (*buffer_budget_mb != 128U && *buffer_budget_mb != 512U && *buffer_budget_mb != 1024U) {
            setStatusText(QStringLiteral("Unsupported buffer memory budget preset for per-flow smart export."), true);
            return false;
        }

        const auto max_megabytes = static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max() / (1024ULL * 1024ULL));
        if (*buffer_budget_mb > max_megabytes) {
            setStatusText(QStringLiteral("Per-flow smart export buffer memory budget is out of range."), true);
            return false;
        }

        ++active_smart_export_job_id_;
        const auto job_id = active_smart_export_job_id_;
        smart_export_cancel_token_ = std::make_shared<std::atomic_bool>(false);
        smart_export_cancel_requested_ = false;

        const SmartPerFlowExportOptions options {
            .buffer_budget_bytes = static_cast<std::size_t>(*buffer_budget_mb * 1024ULL * 1024ULL),
            .progress_callback = [this, job_id](const SmartPerFlowExportProgress& progress) {
                QMetaObject::invokeMethod(
                    this,
                    [this, job_id, progress]() {
                        updateSmartExportProgress(
                            job_id,
                            progress.phase,
                            static_cast<qulonglong>(progress.packets_processed),
                            static_cast<qulonglong>(progress.total_packets_to_scan),
                            static_cast<qulonglong>(progress.exported_packets_written)
                        );
                    },
                    Qt::QueuedConnection
                );
            },
            .cancel_requested = [token = smart_export_cancel_token_]() {
                return token != nullptr && token->load(std::memory_order_relaxed);
            },
        };

        setSmartExportState(
            true,
            0U,
            static_cast<qulonglong>(request.flow_indices.size()),
            QStringLiteral("Preparing export: flow 0 / %1").arg(QString::number(request.flow_indices.size()))
        );
        setStatusText(QStringLiteral("Smart per-flow export started."));
        smart_export_thread_ = QThread::create([this, job_id, trimmedPath, filesystemPath, request, options]() mutable {
            std::string error_text {};
            const bool exported = session_.export_smart_flows_to_folder(request, filesystemPath, options, &error_text);
            const bool cancelled = error_text == "Smart export cancelled by user.";
            QMetaObject::invokeMethod(this, [this, job_id, trimmedPath, exported, cancelled, error = QString::fromStdString(error_text)]() {
                completeSmartExport(
                    job_id,
                    QStringLiteral("Smart per-flow export completed successfully: %1").arg(trimmedPath),
                    QStringLiteral("Failed to smart-export flows."),
                    exported,
                    cancelled,
                    error
                );
            }, Qt::QueuedConnection);
        });

        QObject::connect(smart_export_thread_, &QThread::finished, smart_export_thread_, &QObject::deleteLater);
        smart_export_thread_->start();
        return true;
    }

    ++active_smart_export_job_id_;
    const auto job_id = active_smart_export_job_id_;
    smart_export_cancel_token_ = std::make_shared<std::atomic_bool>(false);
    smart_export_cancel_requested_ = false;

    const SmartSingleFileExportOptions export_options {
        .progress_callback = [this, job_id](const SmartSingleFileExportProgress& progress) {
            QMetaObject::invokeMethod(
                this,
                [this, job_id, progress]() {
                    updateSmartExportProgress(
                        job_id,
                        SmartPerFlowExportPhase::writing,
                        static_cast<qulonglong>(progress.packets_processed),
                        static_cast<qulonglong>(progress.total_packets_to_scan),
                        static_cast<qulonglong>(progress.exported_packets_written),
                        static_cast<qulonglong>(progress.total_selected_packets)
                    );
                },
                Qt::QueuedConnection
            );
        },
        .cancel_requested = [token = smart_export_cancel_token_]() {
            return token != nullptr && token->load(std::memory_order_relaxed);
        },
    };

    setSmartExportState(true, 0U, 0U, QStringLiteral("Starting smart export..."));
    setStatusText(QStringLiteral("Smart export started."));
    smart_export_thread_ = QThread::create([this, job_id, filesystemPath, request, export_options]() mutable {
        std::string error_text {};
        const bool exported = session_.export_smart_flows_to_pcap(request, filesystemPath, export_options, &error_text);
        const bool cancelled = error_text == "Smart export cancelled by user.";
        QMetaObject::invokeMethod(this, [this, job_id, exported, cancelled, error = QString::fromStdString(error_text)]() {
            completeSmartExport(
                job_id,
                QStringLiteral("Smart export completed successfully."),
                QStringLiteral("Failed to smart-export flows."),
                exported,
                cancelled,
                error
            );
        }, Qt::QueuedConnection);
    });

    QObject::connect(smart_export_thread_, &QThread::finished, smart_export_thread_, &QObject::deleteLater);
    smart_export_thread_->start();
    return true;
}

void MainController::browseCaptureFile() {
    const QString path = chooseFile(false);
    if (!path.isEmpty()) {
        openCaptureFile(path);
    }
}

void MainController::browseIndexFile() {
    const QString path = chooseFile(true);
    if (!path.isEmpty()) {
        openIndexFile(path);
    }
}

void MainController::browseAttachSourceCapture() {
    const QString path = chooseFile(false);
    if (!path.isEmpty()) {
        attachSourceCapture(path);
    }
}

void MainController::browseSaveAnalysisIndex() {
    const QString path = chooseSaveFile(true);
    if (!path.isEmpty()) {
        saveAnalysisIndex(path);
    }
}

void MainController::browseExportSelectedFlow() {
    const QString path = chooseSaveFile(false);
    if (!path.isEmpty()) {
        exportSelectedFlow(path);
    }
}

void MainController::browseExportSelectedFlowSequenceCsv() {
    const QString path = chooseSequenceCsvSaveFile();
    if (!path.isEmpty()) {
        exportSelectedFlowSequenceCsv(path);
    }
}

void MainController::browseExportSelectedFlows() {
    const QString path = chooseSaveFile(false);
    if (!path.isEmpty()) {
        exportSelectedFlows(path);
    }
}

void MainController::browseExportUnselectedFlows() {
    const QString path = chooseSaveFile(false);
    if (!path.isEmpty()) {
        exportUnselectedFlows(path);
    }
}

void MainController::browseExportAllFlowsInfoCsv() {
    const QString path = chooseFlowInfoCsvSaveFile();
    if (!path.isEmpty()) {
        exportAllFlowsInfoCsv(path);
    }
}

void MainController::browseExportProtocolPathTree() {
    const QString path = chooseProtocolPathTreeSaveFile();
    if (!path.isEmpty()) {
        exportProtocolPathTree(path);
    }
}

bool MainController::browseSmartExportFlows(
    const int outputMode,
    const int flowScopeMode,
    const int baseSelectionMode,
    const QString& packetCountText,
    const QString& originalBytesText,
    const QString& destinationFolderText,
    const QString& bufferBudgetPresetText,
    const bool includeLastPacket,
    const bool includeEveryKthPacket,
    const QString& everyKText
) {
    if (flowScopeMode == kSmartExportFlowScopeUnrecognizedPackets &&
        outputMode == kSmartExportOutputModeSeparateFilePerFlow) {
        setStatusText(QStringLiteral("Unrecognized packets can only be smart-exported to a single output file."), true);
        return false;
    }

    const QString path = outputMode == kSmartExportOutputModeSeparateFilePerFlow
        ? destinationFolderText.trimmed()
        : chooseSaveFile(false);
    if (path.isEmpty()) {
        if (outputMode == kSmartExportOutputModeSeparateFilePerFlow) {
            setStatusText(QStringLiteral("No destination folder selected for smart export."), true);
        }
        return false;
    }

    return exportSmartFlows(
        path,
        outputMode,
        flowScopeMode,
        baseSelectionMode,
        packetCountText,
        originalBytesText,
        bufferBudgetPresetText,
        includeLastPacket,
        includeEveryKthPacket,
        everyKText
    );
}

QString MainController::chooseSmartExportDestinationFolder() const {
    return chooseDirectory(QStringLiteral("Choose Smart Export Destination Folder"));
}

void MainController::copySelectedFlowWiresharkFilter() {
    const auto filter = selectedFlowWiresharkFilter();
    if (filter.isEmpty()) {
        return;
    }

    if (auto* clipboard = QGuiApplication::clipboard(); clipboard != nullptr) {
        clipboard->setText(filter);
    }
}

void MainController::copyTextToClipboard(const QString& text) {
    if (text.isEmpty()) {
        return;
    }

    if (auto* clipboard = QGuiApplication::clipboard(); clipboard != nullptr) {
        clipboard->setText(text);
    }
}

void MainController::useAdvancedFlowFilter() {
    if (flow_filter_mode_ == FlowFilterMode::advanced) {
        return;
    }

    flow_filter_mode_ = FlowFilterMode::advanced;
    applyActiveFlowFilterModeToModel();
    emit flowFilterModeChanged();
    emit smartExportCurrentFilterAvailableChanged();
}

void MainController::useSimpleFlowFilter() {
    if (flow_filter_mode_ == FlowFilterMode::simple) {
        return;
    }

    flow_filter_mode_ = FlowFilterMode::simple;
    applyActiveFlowFilterModeToModel();
    emit flowFilterModeChanged();
    emit smartExportCurrentFilterAvailableChanged();
}

void MainController::clearAdvancedFlowFilter() {
    if (!advancedFlowFilterClearAvailable()) {
        return;
    }

    const bool editing = advanced_flow_filter_document_state_.is_editing();
    const bool has_unsynchronized_buffered_changes =
        advanced_flow_filter_editor_model_.hasUnsynchronizedBufferedChanges();
    const bool file_backed_dirty =
        advanced_flow_filter_document_state_.source_path() != nullptr &&
        (advanced_flow_filter_document_state_.has_unsaved_changes() || has_unsynchronized_buffered_changes);
    if (advanced_flow_filter_document_state_.would_lose_unsaved_configuration() || has_unsynchronized_buffered_changes) {
        switch (confirmAdvancedFlowFilterClear(file_backed_dirty)) {
        case AdvancedFlowFilterClearDecision::save_and_clear:
            if (!saveAdvancedFlowFilterFile()) {
                if (!editing && !advanced_flow_filter_editor_model_.validationText().isEmpty()) {
                    setStatusText(advanced_flow_filter_editor_model_.validationText(), true);
                }
                return;
            }
            break;
        case AdvancedFlowFilterClearDecision::save_as_and_clear:
            if (!saveAdvancedFlowFilterFileAs()) {
                if (!editing && !advanced_flow_filter_editor_model_.validationText().isEmpty()) {
                    setStatusText(advanced_flow_filter_editor_model_.validationText(), true);
                }
                return;
            }
            break;
        case AdvancedFlowFilterClearDecision::discard_and_clear:
            break;
        case AdvancedFlowFilterClearDecision::cancel:
            return;
        }
    }

    finalizeAdvancedFlowFilterClearAll();
}

void MainController::clearAdvancedFlowFilterUnsavedChanges() {
    if (advanced_flow_filter_document_state_.saved_baseline() == nullptr ||
        (!advanced_flow_filter_document_state_.can_clear_unsaved_changes() &&
         !advanced_flow_filter_editor_model_.hasUnsynchronizedBufferedChanges())) {
        return;
    }

    if (!advanced_flow_filter_document_state_.revert_to_saved_baseline()) {
        return;
    }

    refreshAdvancedFlowFilterEditingPresentation();
}

void MainController::beginAdvancedFlowFilterEdit() {
    advanced_flow_filter_document_state_.begin_edit();
    advanced_flow_filter_editor_model_.initializeFromCurrentDocument();
    refreshAdvancedFlowFilterProtocolPathApplicability();
}

void MainController::cancelAdvancedFlowFilterEdit() {
    if (!advanced_flow_filter_document_state_.is_editing()) {
        return;
    }

    advanced_flow_filter_document_state_.cancel_edit();
    advanced_flow_filter_editor_model_.clearTransientState();
    advanced_flow_filter_protocol_path_selector_model_.clearSelection();
    advanced_flow_filter_protocol_path_selector_row_ = -1;
}

bool MainController::applyAdvancedFlowFilterEdit() {
    QString validation_error {};
    if (!advanced_flow_filter_editor_model_.synchronizeDraftSections(&validation_error)) {
        advanced_flow_filter_editor_model_.setValidationText(validation_error);
        return false;
    }

    if (!advanced_flow_filter_document_state_.apply_draft()) {
        return false;
    }

    advanced_flow_filter_editor_model_.clearTransientState();
    advanced_flow_filter_protocol_path_selector_model_.clearSelection();
    advanced_flow_filter_protocol_path_selector_row_ = -1;
    refreshAdvancedFlowFilter();
    emit smartExportCurrentFilterAvailableChanged();
    return true;
}

void MainController::openAdvancedFlowFilterFile() {
    const bool has_unsynchronized_buffered_changes =
        advanced_flow_filter_editor_model_.hasUnsynchronizedBufferedChanges();
    const bool file_backed_dirty =
        advanced_flow_filter_document_state_.source_path() != nullptr
        && (advanced_flow_filter_document_state_.has_unsaved_changes() || has_unsynchronized_buffered_changes);
    if (advanced_flow_filter_document_state_.would_lose_unsaved_configuration() || has_unsynchronized_buffered_changes) {
        switch (confirmAdvancedFlowFilterOpenUnsaved(file_backed_dirty)) {
        case AdvancedFlowFilterOpenUnsavedDecision::save_and_open:
            if (!saveAdvancedFlowFilterFile()) {
                return;
            }
            break;
        case AdvancedFlowFilterOpenUnsavedDecision::save_as_and_open:
            if (!saveAdvancedFlowFilterFileAs()) {
                return;
            }
            break;
        case AdvancedFlowFilterOpenUnsavedDecision::discard_and_open:
            break;
        case AdvancedFlowFilterOpenUnsavedDecision::cancel:
            return;
        }
    }

    const QString selected_path = chooseAdvancedFlowFilterOpenFile();
    if (selected_path.trimmed().isEmpty()) {
        return;
    }

    QString error_text {};
    if (!openAdvancedFlowFilterFileAtPath(std::filesystem::path {selected_path.toStdWString()}, &error_text)) {
        advanced_flow_filter_editor_model_.setValidationText(error_text);
    }
}

bool MainController::saveAdvancedFlowFilterFile() {
    QString validation_error {};
    if (!synchronizeAdvancedFlowFilterDraft(&validation_error)) {
        advanced_flow_filter_editor_model_.setValidationText(validation_error);
        return false;
    }

    const auto* source_path = advanced_flow_filter_document_state_.source_path();
    if (source_path == nullptr) {
        return saveAdvancedFlowFilterFileAs();
    }

    QString error_text {};
    if (!saveAdvancedFlowFilterDraftToPath(*source_path, &error_text)) {
        advanced_flow_filter_editor_model_.setValidationText(error_text);
        return false;
    }

    return true;
}

bool MainController::saveAdvancedFlowFilterFileAs() {
    QString validation_error {};
    if (!synchronizeAdvancedFlowFilterDraft(&validation_error)) {
        advanced_flow_filter_editor_model_.setValidationText(validation_error);
        return false;
    }

    const QString selected_path = chooseAdvancedFlowFilterSaveAsFile(advancedFlowFilterSuggestedFileName());
    if (selected_path.trimmed().isEmpty()) {
        return false;
    }

    QString error_text {};
    if (!saveAdvancedFlowFilterDraftToPath(std::filesystem::path {selected_path.toStdWString()}, &error_text)) {
        advanced_flow_filter_editor_model_.setValidationText(error_text);
        return false;
    }

    return true;
}

void MainController::setAdvancedFlowFilterOpenFileChooserForTests(std::function<QString()> chooser) {
    advanced_flow_filter_open_file_chooser_for_tests_ = std::move(chooser);
}

void MainController::setAdvancedFlowFilterSaveAsFileChooserForTests(
    std::function<QString(const QString& suggestedFileName)> chooser
) {
    advanced_flow_filter_save_as_file_chooser_for_tests_ = std::move(chooser);
}

void MainController::setAdvancedFlowFilterUnsavedOpenDecisionForTests(
    std::function<AdvancedFlowFilterOpenUnsavedDecision(bool fileBackedDirty)> resolver
) {
    advanced_flow_filter_unsaved_open_decision_for_tests_ = std::move(resolver);
}

void MainController::setAdvancedFlowFilterClearDecisionForTests(
    std::function<AdvancedFlowFilterClearDecision(bool fileBackedDirty)> resolver
) {
    advanced_flow_filter_clear_decision_for_tests_ = std::move(resolver);
}

void MainController::setAdvancedFlowFilterSaveErrorForTests(
    std::function<std::optional<QString>(const std::filesystem::path& path)> provider
) {
    advanced_flow_filter_save_error_for_tests_ = std::move(provider);
}

void MainController::setAdvancedFlowFilterSectionEnabled(const int section, const bool enabled) {
    advanced_flow_filter_editor_model_.setSectionEnabled(section, enabled);
}

void MainController::setAdvancedFlowFilterOptionChecked(
    const int section,
    const int value,
    const bool exclude,
    const bool checked
) {
    advanced_flow_filter_editor_model_.setOptionChecked(section, value, exclude, checked);
}

void MainController::addAdvancedFlowFilterPortRow(const bool exclude) {
    advanced_flow_filter_editor_model_.addPortRow(exclude);
}

void MainController::removeAdvancedFlowFilterPortRow(const bool exclude, const int row) {
    advanced_flow_filter_editor_model_.removePortRow(exclude, row);
}

void MainController::setAdvancedFlowFilterPortRowScope(const bool exclude, const int row, const int scope) {
    advanced_flow_filter_editor_model_.setPortRowScope(exclude, row, scope);
}

void MainController::setAdvancedFlowFilterPortRowRangeEnabled(const bool exclude, const int row, const bool enabled) {
    advanced_flow_filter_editor_model_.setPortRowRangeEnabled(exclude, row, enabled);
}

void MainController::setAdvancedFlowFilterPortRowPrimaryText(const bool exclude, const int row, const QString& text) {
    advanced_flow_filter_editor_model_.setPortRowPrimaryText(exclude, row, text);
}

void MainController::setAdvancedFlowFilterPortRowSecondaryText(const bool exclude, const int row, const QString& text) {
    advanced_flow_filter_editor_model_.setPortRowSecondaryText(exclude, row, text);
}

void MainController::addAdvancedFlowFilterAddressRow(const bool exclude) {
    advanced_flow_filter_editor_model_.addAddressRow(exclude);
}

void MainController::removeAdvancedFlowFilterAddressRow(const bool exclude, const int row) {
    advanced_flow_filter_editor_model_.removeAddressRow(exclude, row);
}

void MainController::setAdvancedFlowFilterAddressRowScope(const bool exclude, const int row, const int scope) {
    advanced_flow_filter_editor_model_.setAddressRowScope(exclude, row, scope);
}

void MainController::setAdvancedFlowFilterAddressRowSubnetEnabled(const bool exclude, const int row, const bool enabled) {
    advanced_flow_filter_editor_model_.setAddressRowSubnetEnabled(exclude, row, enabled);
}

void MainController::setAdvancedFlowFilterAddressRowAddressText(const bool exclude, const int row, const QString& text) {
    advanced_flow_filter_editor_model_.setAddressRowAddressText(exclude, row, text);
}

void MainController::setAdvancedFlowFilterAddressRowPrefixText(const bool exclude, const int row, const QString& text) {
    advanced_flow_filter_editor_model_.setAddressRowPrefixText(exclude, row, text);
}

void MainController::beginAdvancedFlowFilterProtocolPathSelection(const bool exclude, const int row) {
    advanced_flow_filter_protocol_path_selector_exclude_ = exclude;
    advanced_flow_filter_protocol_path_selector_row_ = row;
    advanced_flow_filter_protocol_path_selector_model_.setCaptureSession(&session_);
    const auto current_rows = advanced_flow_filter_editor_model_.protocolPathRows(exclude);
    if (row >= 0 && row < current_rows.size()) {
        auto* draft_document = advanced_flow_filter_document_state_.draft_document();
        if (draft_document != nullptr) {
            const auto& predicates = exclude
                ? draft_document->configured_spec.protocol_path.exclude
                : draft_document->configured_spec.protocol_path.include;
            int ui_index = -1;
            for (const auto& predicate : predicates) {
                if (predicate.match_kind == session_detail::AdvancedFlowFilterProtocolPathMatchKind::contains_layer) {
                    continue;
                }
                ++ui_index;
                if (ui_index == row) {
                    advanced_flow_filter_protocol_path_selector_model_.selectPredicate(predicate);
                    return;
                }
            }
        }
    }

    advanced_flow_filter_protocol_path_selector_model_.setMode(kProtocolPathStatisticsModeKindOverview);
    advanced_flow_filter_protocol_path_selector_model_.clearSelection();
}

bool MainController::applyAdvancedFlowFilterProtocolPathSelection() {
    const auto predicate = advanced_flow_filter_protocol_path_selector_model_.selectedPredicate();
    if (!predicate.has_value()) {
        return false;
    }

    advanced_flow_filter_editor_model_.upsertProtocolPathRow(
        advanced_flow_filter_protocol_path_selector_exclude_,
        advanced_flow_filter_protocol_path_selector_row_,
        *predicate,
        static_cast<ProtocolPathStatisticsMode>(advanced_flow_filter_protocol_path_selector_model_.mode())
    );
    refreshAdvancedFlowFilterProtocolPathApplicability();
    advanced_flow_filter_protocol_path_selector_row_ = -1;
    return true;
}

void MainController::removeAdvancedFlowFilterProtocolPathRow(const bool exclude, const int row) {
    advanced_flow_filter_editor_model_.removeProtocolPathRow(exclude, row);
}

void MainController::sortFlows(const int column) {
    const auto requestedKey = sort_key_from_column(column);

    if (flow_model_.sortKey() == requestedKey) {
        flow_model_.setSortAscending(!flow_model_.sortAscending());
    } else {
        flow_model_.setSortKey(requestedKey);
        flow_model_.setSortAscending(true);
    }

    synchronizeFlowSelection();
    emit flowSortChanged();
}

void MainController::drillDownToFlows(const QString& filterText) {
    setCurrentTabIndex(kFlowTabIndex);
    clearFlowSelection();
    useSimpleFlowFilter();
    setFlowFilterText(filterText.trimmed());
}

void MainController::drillDownToEndpoint(const QString& endpointText) {
    drillDownToFlows(endpointText);
}

void MainController::drillDownToPort(const quint32 port) {
    drillDownToFlows(QString::number(port));
}

void MainController::showSelectedProtocolPathFlows() {
    if (!session_.has_capture() || !protocol_path_stats_model_.hasSelectedNode()) {
        return;
    }

    const auto mode = protocol_path_statistics_mode_from_int(statistics_mode_);
    const auto node_id = static_cast<std::uint64_t>(protocol_path_stats_model_.selectedNodeId());
    const auto flow_indices = session_.protocol_path_summary_flow_indices(mode, node_id);

    std::vector<int> snapshot_flow_indices {};
    snapshot_flow_indices.reserve(flow_indices.size());
    for (const auto flow_index : flow_indices) {
        snapshot_flow_indices.push_back(static_cast<int>(flow_index));
    }

    has_active_protocol_path_filter_ = true;
    active_protocol_path_filter_mode_ = mode;
    active_protocol_path_filter_node_id_ = node_id;
    active_protocol_path_filter_flow_indices_ = snapshot_flow_indices;
    active_protocol_path_filter_label_ = QStringLiteral("%1 / %2").arg(
        protocol_path_statistics_mode_label(mode),
        protocol_path_stats_model_.selectedNodeFilterLabel()
    );

    flow_model_.setAllowedFlowIndices(std::move(snapshot_flow_indices));
    setCurrentTabIndex(kFlowTabIndex);
    synchronizeFlowSelection();
    emit protocolPathFlowFilterChanged();
}

void MainController::setStatisticsSectionState(
    const StatisticsOptionalSection section,
    const StatisticsSectionRequestState state,
    QString errorText
) {
    switch (section) {
    case StatisticsOptionalSection::packet_size_distribution:
        packet_size_distribution_state_ = state;
        packet_size_distribution_error_text_ = std::move(errorText);
        break;
    case StatisticsOptionalSection::flow_packet_histogram:
        flow_packet_histogram_state_ = state;
        flow_packet_histogram_error_text_ = std::move(errorText);
        break;
    case StatisticsOptionalSection::protocol_path:
        protocol_path_section_state_ = state;
        protocol_path_error_text_ = std::move(errorText);
        break;
    case StatisticsOptionalSection::protocol_hints:
        protocol_hints_section_state_ = state;
        protocol_hints_error_text_ = std::move(errorText);
        break;
    case StatisticsOptionalSection::quic_tls:
        quic_tls_section_state_ = state;
        quic_tls_error_text_ = std::move(errorText);
        break;
    case StatisticsOptionalSection::top_endpoints_ports:
        top_endpoints_ports_section_state_ = state;
        top_endpoints_ports_error_text_ = std::move(errorText);
        break;
    }
}

QString MainController::statisticsSectionStatusText(const StatisticsOptionalSection section) const {
    StatisticsSectionRequestState state {StatisticsSectionRequestState::not_requested};
    QString error_text {};

    switch (section) {
    case StatisticsOptionalSection::packet_size_distribution:
        state = packet_size_distribution_state_;
        error_text = packet_size_distribution_error_text_;
        break;
    case StatisticsOptionalSection::flow_packet_histogram:
        state = flow_packet_histogram_state_;
        error_text = flow_packet_histogram_error_text_;
        break;
    case StatisticsOptionalSection::protocol_path:
        state = protocol_path_section_state_;
        error_text = protocol_path_error_text_;
        break;
    case StatisticsOptionalSection::protocol_hints:
        state = protocol_hints_section_state_;
        error_text = protocol_hints_error_text_;
        break;
    case StatisticsOptionalSection::quic_tls:
        state = quic_tls_section_state_;
        error_text = quic_tls_error_text_;
        break;
    case StatisticsOptionalSection::top_endpoints_ports:
        state = top_endpoints_ports_section_state_;
        error_text = top_endpoints_ports_error_text_;
        break;
    }

    switch (state) {
    case StatisticsSectionRequestState::loading:
        if (section == StatisticsOptionalSection::packet_size_distribution) {
            return QStringLiteral("Loading packet-size distribution...");
        }
        return QStringLiteral("Calculating...");
    case StatisticsSectionRequestState::unavailable:
        return QStringLiteral("Statistics are unavailable for this capture.");
    case StatisticsSectionRequestState::error:
        return error_text.isEmpty() ? QStringLiteral("Failed to calculate this section.") : error_text;
    case StatisticsSectionRequestState::not_requested:
    case StatisticsSectionRequestState::ready:
        return {};
    }

    return {};
}

void MainController::resetStatisticsSectionState(const bool emitResetToken) {
    packet_size_distribution_expanded_ = false;
    flow_packet_histogram_expanded_ = false;
    protocol_path_section_expanded_ = false;
    protocol_hints_section_expanded_ = false;
    quic_tls_section_expanded_ = false;
    top_endpoints_ports_section_expanded_ = false;

    packet_size_statistics_ = {};
    packet_size_distribution_rows_.clear();
    flow_packet_count_histogram_ = {};
    flow_packet_histogram_rows_.clear();
    protocol_hint_distribution_.clear();
    protocol_path_summary_ = {};
    protocol_path_stats_model_.clear();
    loaded_protocol_path_statistics_mode_ = -1;
    protocol_path_stats_model_.resetExpandedStateForMode(statistics_mode_);
    quic_recognition_stats_ = {};
    tls_recognition_stats_ = {};
    top_endpoints_model_.clear();
    top_ports_model_.clear();

    setStatisticsSectionState(StatisticsOptionalSection::packet_size_distribution, StatisticsSectionRequestState::not_requested);
    setStatisticsSectionState(StatisticsOptionalSection::flow_packet_histogram, StatisticsSectionRequestState::not_requested);
    setStatisticsSectionState(StatisticsOptionalSection::protocol_path, StatisticsSectionRequestState::not_requested);
    setStatisticsSectionState(StatisticsOptionalSection::protocol_hints, StatisticsSectionRequestState::not_requested);
    setStatisticsSectionState(StatisticsOptionalSection::quic_tls, StatisticsSectionRequestState::not_requested);
    setStatisticsSectionState(StatisticsOptionalSection::top_endpoints_ports, StatisticsSectionRequestState::not_requested);

    if (emitResetToken) {
        ++statistics_sections_reset_token_;
        emit statisticsSectionsResetTokenChanged();
    }
}

void MainController::ensurePacketSizeDistributionLoaded() {
    if (!packet_size_distribution_expanded_) {
        return;
    }
    if (current_tab_index_ != kStatsTabIndex) {
        return;
    }
    if (!session_.has_capture()) {
        setStatisticsSectionState(StatisticsOptionalSection::packet_size_distribution, StatisticsSectionRequestState::unavailable);
        emit stateChanged();
        return;
    }
    if (packet_size_distribution_state_ == StatisticsSectionRequestState::ready) {
        return;
    }

    setStatisticsSectionState(StatisticsOptionalSection::packet_size_distribution, StatisticsSectionRequestState::loading);
    emit stateChanged();
    packet_size_statistics_ = session_.packet_size_statistics();
    packet_size_distribution_rows_ = build_packet_size_distribution_rows(packet_size_statistics_);
    setStatisticsSectionState(StatisticsOptionalSection::packet_size_distribution, StatisticsSectionRequestState::ready);
    emit stateChanged();
}

void MainController::ensureFlowPacketHistogramLoaded() {
    if (!flow_packet_histogram_expanded_) {
        return;
    }
    if (current_tab_index_ != kStatsTabIndex) {
        return;
    }
    if (!session_.has_capture()) {
        setStatisticsSectionState(StatisticsOptionalSection::flow_packet_histogram, StatisticsSectionRequestState::unavailable);
        emit stateChanged();
        return;
    }
    if (flow_packet_histogram_state_ == StatisticsSectionRequestState::ready) {
        return;
    }

    setStatisticsSectionState(StatisticsOptionalSection::flow_packet_histogram, StatisticsSectionRequestState::loading);
    emit stateChanged();
    flow_packet_count_histogram_ = session_.flow_packet_count_histogram();
    flow_packet_histogram_rows_ = build_flow_packet_histogram_rows(flow_packet_count_histogram_);
    setStatisticsSectionState(StatisticsOptionalSection::flow_packet_histogram, StatisticsSectionRequestState::ready);
    emit stateChanged();
}

void MainController::ensureProtocolHintsLoaded() {
    if (!protocol_hints_section_expanded_) {
        return;
    }
    if (current_tab_index_ != kStatsTabIndex) {
        return;
    }
    if (!session_.has_capture()) {
        setStatisticsSectionState(StatisticsOptionalSection::protocol_hints, StatisticsSectionRequestState::unavailable);
        emit stateChanged();
        return;
    }
    if (protocol_hints_section_state_ == StatisticsSectionRequestState::ready) {
        return;
    }

    setStatisticsSectionState(StatisticsOptionalSection::protocol_hints, StatisticsSectionRequestState::loading);
    emit stateChanged();
    protocol_hint_distribution_ = build_protocol_hint_distribution_rows(protocol_summary_);
    setStatisticsSectionState(StatisticsOptionalSection::protocol_hints, StatisticsSectionRequestState::ready);
    emit stateChanged();
}

void MainController::ensureProtocolPathStatisticsLoaded() {
    ensureProtocolPathSectionLoaded();
}

void MainController::ensureProtocolPathSectionLoaded() {
    if (!protocol_path_section_expanded_) {
        return;
    }
    if (current_tab_index_ != kStatsTabIndex) {
        return;
    }
    if (!session_.has_capture()) {
        setStatisticsSectionState(StatisticsOptionalSection::protocol_path, StatisticsSectionRequestState::unavailable);
        emit stateChanged();
        return;
    }

    const auto current_mode = protocol_path_statistics_mode_from_int(statistics_mode_);
    if (protocol_path_section_state_ == StatisticsSectionRequestState::ready &&
        loaded_protocol_path_statistics_mode_ == statistics_mode_) {
        return;
    }

    setStatisticsSectionState(StatisticsOptionalSection::protocol_path, StatisticsSectionRequestState::loading);
    emit stateChanged();
    protocol_path_summary_ = session_.protocol_path_summary(current_mode);
    protocol_path_stats_model_.refresh(protocol_path_summary_);
    loaded_protocol_path_statistics_mode_ = statistics_mode_;
    setStatisticsSectionState(StatisticsOptionalSection::protocol_path, StatisticsSectionRequestState::ready);
    emit stateChanged();
}

void MainController::ensureQuicTlsSectionLoaded() {
    if (!quic_tls_section_expanded_) {
        return;
    }
    if (current_tab_index_ != kStatsTabIndex) {
        return;
    }
    if (!session_.has_capture()) {
        setStatisticsSectionState(StatisticsOptionalSection::quic_tls, StatisticsSectionRequestState::unavailable);
        emit stateChanged();
        return;
    }
    if (quic_tls_section_state_ == StatisticsSectionRequestState::ready) {
        return;
    }

    setStatisticsSectionState(StatisticsOptionalSection::quic_tls, StatisticsSectionRequestState::loading);
    emit stateChanged();
    const auto summary = session_.quic_tls_summary();
    quic_recognition_stats_ = summary.quic;
    tls_recognition_stats_ = summary.tls;
    setStatisticsSectionState(StatisticsOptionalSection::quic_tls, StatisticsSectionRequestState::ready);
    emit stateChanged();
}

void MainController::ensureTopEndpointsAndPortsSectionLoaded() {
    if (!top_endpoints_ports_section_expanded_) {
        return;
    }
    if (current_tab_index_ != kStatsTabIndex) {
        return;
    }
    if (!session_.has_capture()) {
        setStatisticsSectionState(StatisticsOptionalSection::top_endpoints_ports, StatisticsSectionRequestState::unavailable);
        emit stateChanged();
        return;
    }
    if (top_endpoints_ports_section_state_ == StatisticsSectionRequestState::ready) {
        return;
    }

    setStatisticsSectionState(StatisticsOptionalSection::top_endpoints_ports, StatisticsSectionRequestState::loading);
    emit stateChanged();
    refreshTopSummaryModels();
    setStatisticsSectionState(StatisticsOptionalSection::top_endpoints_ports, StatisticsSectionRequestState::ready);
    emit stateChanged();
}

void MainController::maybeLoadExpandedStatisticsSections() {
    ensurePacketSizeDistributionLoaded();
    ensureFlowPacketHistogramLoaded();
    ensureProtocolPathSectionLoaded();
    ensureProtocolHintsLoaded();
    ensureQuicTlsSectionLoaded();
    ensureTopEndpointsAndPortsSectionLoaded();
}

void MainController::setStatisticsSectionExpanded(const int section, const bool expanded) {
    const auto normalized_section = static_cast<StatisticsOptionalSection>(section);
    switch (normalized_section) {
    case StatisticsOptionalSection::packet_size_distribution:
        packet_size_distribution_expanded_ = expanded;
        break;
    case StatisticsOptionalSection::flow_packet_histogram:
        flow_packet_histogram_expanded_ = expanded;
        break;
    case StatisticsOptionalSection::protocol_path:
        protocol_path_section_expanded_ = expanded;
        break;
    case StatisticsOptionalSection::protocol_hints:
        protocol_hints_section_expanded_ = expanded;
        break;
    case StatisticsOptionalSection::quic_tls:
        quic_tls_section_expanded_ = expanded;
        break;
    case StatisticsOptionalSection::top_endpoints_ports:
        top_endpoints_ports_section_expanded_ = expanded;
        break;
    }

    if (expanded) {
        maybeLoadExpandedStatisticsSections();
    }
}

void MainController::clearProtocolPathFlowFilter() {
    if (!clearProtocolPathFlowFilterState()) {
        return;
    }

    synchronizeFlowSelection();
    emit protocolPathFlowFilterChanged();
}

void MainController::setFlowDetailsTabIndex(const int index) {
    const bool streamActive = index == 1;
    if (streamActive && unrecognized_packets_selected_) {
        if (stream_tab_active_) {
            stream_tab_active_ = false;
            emit streamListStateChanged();
        }
        details_selection_context_ = DetailsSelectionContext::none;
        packet_details_model_.clear();
        return;
    }

    if (stream_tab_active_ == streamActive) {
        return;
    }

    stream_tab_active_ = streamActive;
    if (stream_tab_active_ && selected_flow_index_ >= 0 && !stream_state_materialized_for_selected_flow_) {
        if (ensureSourceCaptureAvailable()) {
            stream_loading_ = true;
            emit streamListStateChanged();
            QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents, 5);
            refreshSelectedStreamItems(true);
        }
    }

    if (stream_tab_active_) {
        if (selected_stream_item_index_ != kInvalidStreamSelection) {
            details_selection_context_ = DetailsSelectionContext::stream;
            reloadSelectedStreamDetails();
        } else if (selected_flow_index_ >= 0 && !session_.has_source_capture()) {
            details_selection_context_ = DetailsSelectionContext::none;
            showSourceUnavailableStreamDetailsPlaceholder();
        } else {
            details_selection_context_ = DetailsSelectionContext::none;
            packet_details_model_.clear();
        }
        return;
    }

    if (selected_packet_index_ != kInvalidPacketSelection) {
        details_selection_context_ = DetailsSelectionContext::packet;
        reloadSelectedPacketDetails();
    } else {
        details_selection_context_ = DetailsSelectionContext::none;
        packet_details_model_.clear();
    }

}

void MainController::setStatisticsMode(const int mode) {
    const int normalizedMode = (mode == kProtocolPathStatisticsModeIdentityTree)
        ? kProtocolPathStatisticsModeIdentityTree
        : (mode == kProtocolPathStatisticsModeTerminalPaths
            ? kProtocolPathStatisticsModeTerminalPaths
            : kProtocolPathStatisticsModeKindOverview);

    if (statistics_mode_ == normalizedMode) {
        return;
    }

    statistics_mode_ = normalizedMode;
    protocol_path_summary_ = {};
    loaded_protocol_path_statistics_mode_ = -1;
    protocol_path_stats_model_.clear();
    protocol_path_stats_model_.resetExpandedStateForMode(statistics_mode_);
    setStatisticsSectionState(StatisticsOptionalSection::protocol_path, StatisticsSectionRequestState::not_requested);
    if (session_.has_capture() && current_tab_index_ == kStatsTabIndex && protocol_path_section_expanded_) {
        ensureProtocolPathSectionLoaded();
    }
    emit stateChanged();
    emit statisticsModeChanged();
}

void MainController::setHttpUsePathAsServiceHint(const bool enabled) {
    if (pending_analysis_settings_.http_use_path_as_service_hint == enabled) {
        return;
    }

    pending_analysis_settings_.http_use_path_as_service_hint = enabled;
    emit httpUsePathAsServiceHintChanged();

    if (session_.has_capture()) {
        setStatusText(
            QStringLiteral("Settings updated. Capture-processing changes apply when a raw capture is opened."),
            false
        );
    }
}

void MainController::setUsePossibleTlsQuic(const bool enabled) {
    if (pending_analysis_settings_.use_possible_tls_quic == enabled) {
        return;
    }

    pending_analysis_settings_.use_possible_tls_quic = enabled;
    session_.set_analysis_settings(pending_analysis_settings_);
    if (session_.has_capture()) {
        protocol_summary_ = session_.protocol_summary();
        flow_model_.refresh(session_.list_flows());
        applyActiveFlowFilterModeToModel();
        if (protocol_hints_section_state_ == StatisticsSectionRequestState::ready) {
            protocol_hint_distribution_ = build_protocol_hint_distribution_rows(protocol_summary_);
        }
        if (analysis_tab_active_ && selected_flow_index_ >= 0) {
            refreshSelectedFlowAnalysis();
        }
        emit stateChanged();
    }
    emit usePossibleTlsQuicChanged();
}

void MainController::setIgnoreVlanAndMplsLayersWhenGroupingFlows(const bool enabled) {
    if (pending_analysis_settings_.ignore_vlan_and_mpls_layers_when_grouping_flows == enabled) {
        return;
    }

    pending_analysis_settings_.ignore_vlan_and_mpls_layers_when_grouping_flows = enabled;
    session_.set_analysis_settings(pending_analysis_settings_);
    emit ignoreVlanAndMplsLayersWhenGroupingFlowsChanged();
    if (session_.has_capture()) {
        setStatusText(
            session_.opened_from_index()
                ? QStringLiteral("Settings updated. Capture-processing changes apply when a raw capture is opened.")
                : QStringLiteral("Reopen the current raw capture to apply the VLAN and MPLS flow-grouping setting."),
            false
        );
        emit stateChanged();
    }
}

void MainController::setIgnoreGtpuTeidsWhenGroupingInnerFlows(const bool enabled) {
    if (pending_analysis_settings_.ignore_gtpu_teids_when_grouping_inner_flows == enabled) {
        return;
    }

    pending_analysis_settings_.ignore_gtpu_teids_when_grouping_inner_flows = enabled;
    session_.set_analysis_settings(pending_analysis_settings_);
    emit ignoreGtpuTeidsWhenGroupingInnerFlowsChanged();
    if (session_.has_capture()) {
        setStatusText(
            session_.opened_from_index()
                ? QStringLiteral("Settings updated. Capture-processing changes apply when a raw capture is opened.")
                : QStringLiteral("Reopen the current raw capture to apply the GTP-U TEID flow-grouping setting."),
            false
        );
        emit stateChanged();
    }
}

void MainController::setValidateSelectedPacketChecksums(const bool enabled) {
    if (validate_selected_packet_checksums_ == enabled) {
        return;
    }

    validate_selected_packet_checksums_ = enabled;
    emit validateSelectedPacketChecksumsChanged();

    if (details_selection_context_ == DetailsSelectionContext::packet &&
        selected_packet_index_ != kInvalidPacketSelection) {
        reloadSelectedPacketDetails();
    }
}

void MainController::setShowWiresharkFilterForSelectedFlow(const bool enabled) {
    if (show_wireshark_filter_for_selected_flow_ == enabled) {
        return;
    }

    show_wireshark_filter_for_selected_flow_ = enabled;
    emit showWiresharkFilterForSelectedFlowChanged();
    emit selectedFlowWiresharkFilterChanged();
}

void MainController::setShowProtocolPathColumn(const bool enabled) {
    if (show_protocol_path_column_ == enabled) {
        return;
    }

    show_protocol_path_column_ = enabled;
    emit showProtocolPathColumnChanged();
}

void MainController::setShowFragmentedPacketCountColumn(const bool enabled) {
    if (show_fragmented_packet_count_column_ == enabled) {
        return;
    }

    show_fragmented_packet_count_column_ = enabled;
    emit showFragmentedPacketCountColumnChanged();
}

void MainController::setCurrentTabIndex(const int index) {
    const int normalizedIndex = (index == kAnalysisTabIndex || index == kStatsTabIndex || index == kSettingsTabIndex)
        ? index
        : kFlowTabIndex;

    if (current_tab_index_ == normalizedIndex) {
        return;
    }

    current_tab_index_ = normalizedIndex;
    const bool analysisActive = current_tab_index_ == kAnalysisTabIndex;
    if (analysis_tab_active_ != analysisActive) {
        analysis_tab_active_ = analysisActive;
        if (analysis_tab_active_ && selected_flow_index_ >= 0 && !unrecognized_packets_selected_) {
            refreshSelectedFlowAnalysis();
        } else if (!analysis_tab_active_ && analysis_loading_) {
            ++active_analysis_request_id_;
            analysis_loading_ = false;
            emit analysisStateChanged();
        }
    }
    if (current_tab_index_ == kStatsTabIndex) {
        maybeLoadExpandedStatisticsSections();
    }
    emit currentTabIndexChanged();
}

void MainController::setSelectedFlowIndex(const int index) {
    if (selected_flow_index_ == index && !unrecognized_packets_selected_) {
        return;
    }

    if (!analysis_sequence_export_in_progress_ && (!analysis_sequence_export_status_text_.isEmpty() || analysis_sequence_export_status_is_error_)) {
        setAnalysisSequenceExportState(false, {}, false);
    }

    const bool unrecognizedSelectionChanged = unrecognized_packets_selected_;
    unrecognized_packets_selected_ = false;
    selected_flow_index_ = index;
    clearPacketSelection();
    clearStreamSelection();
    clearSelectedFlowAnalysis();
    current_flow_packet_numbers_.clear();
    current_suspected_retransmission_packet_indices_.clear();
    prepared_tcp_contribution_packet_window_count_ = 0U;
    session_.clear_selected_flow_packet_cache();
    session_.clear_selected_flow_tcp_payload_suppression();
    packet_model_.clear();
    current_stream_items_.clear();
    stream_model_.clear();
    total_packet_row_count_ = selected_flow_index_ >= 0
        ? session_.flow_packet_count(static_cast<std::size_t>(selected_flow_index_))
        : 0U;
    loaded_packet_row_count_ = 0U;
    packets_loading_ = selected_flow_index_ >= 0;
    stream_loading_ = selected_flow_index_ >= 0 && stream_tab_active_;
    loaded_stream_item_count_ = 0U;
    total_stream_item_count_ = 0U;
    stream_packet_window_count_ = 0U;
    stream_item_budget_count_ = 0U;
    can_load_more_stream_items_ = false;
    stream_state_materialized_for_selected_flow_ = false;

    emit selectedFlowIndexChanged();
    if (unrecognizedSelectionChanged) {
        emit unrecognizedPacketsSelectionChanged();
    }
    emit selectedFlowWiresharkFilterChanged();
    emit packetListStateChanged();
    emit streamListStateChanged();
    emit actionAvailabilityChanged();

    if (selected_flow_index_ >= 0) {
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents, 5);
        refreshSelectedFlowPackets(true);
        ensureSourceCaptureAvailable();
        maybeEnrichSelectedFlowServiceHint();
        if (stream_tab_active_) {
            refreshSelectedStreamItems(true);
        }
        if (analysis_tab_active_) {
            refreshSelectedFlowAnalysis();
        }
    }

}

void MainController::setSelectedPacketIndex(const qulonglong packetIndex) {
    if (selected_packet_index_ == packetIndex) {
        return;
    }

    selected_packet_index_ = packetIndex;
    if (selected_packet_index_ == kInvalidPacketSelection) {
        if (details_selection_context_ == DetailsSelectionContext::packet) {
            details_selection_context_ = DetailsSelectionContext::none;
            packet_details_model_.clear();
        }
        emit selectedPacketIndexChanged();
        return;
    }

    details_selection_context_ = DetailsSelectionContext::packet;
    reloadSelectedPacketDetails();
    emit selectedPacketIndexChanged();

}

void MainController::selectPacketByteView(const QString& stableId) {
    if (stableId.isEmpty()) {
        return;
    }
    if (details_selection_context_ != DetailsSelectionContext::packet || selected_packet_index_ == kInvalidPacketSelection) {
        return;
    }
    if (selected_packet_byte_view_stable_id_ == stableId) {
        return;
    }

    selected_packet_byte_view_stable_id_ = stableId;
    refreshSelectedPacketByteView();
}

bool MainController::exportSelectedPacketBytes(const QString& formatId) {
    if (formatId.isEmpty()) {
        setStatusText(QStringLiteral("Select an export format."), true);
        return false;
    }
    if (details_selection_context_ != DetailsSelectionContext::packet || selected_packet_index_ == kInvalidPacketSelection) {
        setStatusText(QStringLiteral("Select a packet first."), true);
        return false;
    }
    if (selected_packet_byte_view_stable_id_.isEmpty()) {
        setStatusText(QStringLiteral("Select a byte view first."), true);
        return false;
    }
    if (!packet_details_model_.selectedPacketByteViewAvailable()) {
        setStatusText(QStringLiteral("The selected byte view is unavailable for export."), true);
        return false;
    }
    if (!ensureSourceCaptureAvailable(QStringLiteral("Export packet bytes"))) {
        return false;
    }

    const auto parsed_format = session_detail::parse_byte_export_format_id(formatId.toStdString());
    if (!parsed_format.has_value()) {
        setStatusText(QStringLiteral("Unknown byte export format."), true);
        return false;
    }

    const auto parsed_view_id =
        session_detail::parse_selected_packet_byte_view_stable_id(selected_packet_byte_view_stable_id_.toStdString());
    if (!parsed_view_id.has_value()) {
        setStatusText(QStringLiteral("The selected byte view is invalid for export."), true);
        return false;
    }

    const auto packet = session_.find_packet(static_cast<std::uint64_t>(selected_packet_index_));
    if (!packet.has_value()) {
        setStatusText(QStringLiteral("The selected packet is unavailable for export."), true);
        return false;
    }

    const QString packetNumberText = [&]() -> QString {
        if (unrecognized_packets_selected_) {
            return QString::number(selected_packet_index_ + 1ULL);
        }

        const auto it = current_flow_packet_numbers_.find(packet->packet_index);
        if (it != current_flow_packet_numbers_.end() && it->second > 0U) {
            return QString::number(it->second);
        }
        return QString::number(packet->packet_index + 1ULL);
    }();

    const QString suggestedExtension =
        QString::fromStdString(session_detail::byte_export_format_suggested_extension(*parsed_format));
    const QString suggestedFileName = QStringLiteral("packet-%1-%2.%3").arg(
        packetNumberText,
        sanitize_export_filename_component(packet_details_model_.selectedPacketByteViewLabel()),
        suggestedExtension
    );
    const QString outputPath = chooseByteExportSaveFile(
        QStringLiteral("Export Packet Bytes"),
        suggestedFileName,
        suggestedExtension,
        session_detail::byte_export_format_is_binary(*parsed_format)
    );
    if (outputPath.isEmpty()) {
        return false;
    }

    std::string errorText {};
    if (!session_.export_selected_packet_byte_view(
            *packet,
            *parsed_view_id,
            *parsed_format,
            std::filesystem::path {outputPath.toStdWString()},
            &errorText)) {
        setStatusText(
            errorText.empty()
                ? QStringLiteral("Failed to export the selected packet byte view.")
                : QString::fromStdString(errorText),
            true
        );
        return false;
    }

    setLastDirectoryFromPath(std::filesystem::path {outputPath.toStdWString()});
    setStatusText(QStringLiteral("Packet bytes exported to %1.").arg(outputPath));
    return true;
}

bool MainController::exportSelectedStreamItemData(const QString& formatId) {
    if (formatId.isEmpty()) {
        setStatusText(QStringLiteral("Select an export format."), true);
        return false;
    }
    if (details_selection_context_ != DetailsSelectionContext::stream || selected_stream_item_index_ == kInvalidStreamSelection) {
        setStatusText(QStringLiteral("Select a stream item first."), true);
        return false;
    }
    if (selected_flow_index_ < 0) {
        setStatusText(QStringLiteral("The selected stream item is unavailable for export."), true);
        return false;
    }
    if (!packet_details_model_.streamItemDataAvailable()) {
        setStatusText(QStringLiteral("The selected stream item data is unavailable for export."), true);
        return false;
    }
    if (!ensureSourceCaptureAvailable(QStringLiteral("Export stream item data"))) {
        return false;
    }

    const auto parsed_format = session_detail::parse_byte_export_format_id(formatId.toStdString());
    if (!parsed_format.has_value()) {
        setStatusText(QStringLiteral("Unknown byte export format."), true);
        return false;
    }

    const QString suggestedExtension =
        QString::fromStdString(session_detail::byte_export_format_suggested_extension(*parsed_format));
    const QString suggestedFileName = QStringLiteral("stream-item-%1-%2.%3").arg(
        QString::number(selected_stream_item_index_ + 1ULL),
        sanitize_export_filename_component(packet_details_model_.headerPrimaryText()),
        suggestedExtension
    );
    const QString outputPath = chooseByteExportSaveFile(
        QStringLiteral("Export Stream Item Data"),
        suggestedFileName,
        suggestedExtension,
        session_detail::byte_export_format_is_binary(*parsed_format)
    );
    if (outputPath.isEmpty()) {
        return false;
    }

    const auto limit = loaded_stream_item_count_ > 0U ? loaded_stream_item_count_ : current_stream_items_.size();
    std::string errorText {};
    if (!session_.export_selected_flow_stream_item_data(
            static_cast<std::size_t>(selected_flow_index_),
            stream_packet_window_count_,
            limit,
            static_cast<std::uint64_t>(selected_stream_item_index_),
            *parsed_format,
            std::filesystem::path {outputPath.toStdWString()},
            &errorText)) {
        setStatusText(
            errorText.empty()
                ? QStringLiteral("Failed to export the selected stream item data.")
                : QString::fromStdString(errorText),
            true
        );
        return false;
    }

    setLastDirectoryFromPath(std::filesystem::path {outputPath.toStdWString()});
    setStatusText(QStringLiteral("Stream item data exported to %1.").arg(outputPath));
    return true;
}

void MainController::refreshSelectedPacketByteView() {
    if (details_selection_context_ != DetailsSelectionContext::packet || selected_packet_index_ == kInvalidPacketSelection) {
        return;
    }

    const auto packet = session_.find_packet(static_cast<std::uint64_t>(selected_packet_index_));
    if (!packet.has_value() || !ensureSourceCaptureAvailable()) {
        return;
    }

    const auto packet_bytes = session_.read_packet_data(*packet);
    const auto details = session_.read_packet_details(*packet);
    if (packet_bytes.empty()) {
        packet_details_model_.clearPacketBytePresentation();
        selected_packet_byte_view_stable_id_.clear();
        return;
    }

    std::optional<session_detail::SelectedPacketBytePresentation> packet_byte_presentation {};
    if (details.has_value()) {
        const auto payload_lengths = resolve_transport_payload_lengths(
            *details,
            std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
            *packet
        );
        const auto flow_packet_index = [&]() -> std::optional<std::uint64_t> {
            const auto it = current_flow_packet_numbers_.find(packet->packet_index);
            if (it == current_flow_packet_numbers_.end() || it->second == 0U) {
                return std::nullopt;
            }
            return it->second - 1U;
        }();
        auto packet_summary_preparation = session_detail::prepare_selected_packet_summary(
            session_,
            *details,
            *packet,
            selected_flow_index_ >= 0 ? std::optional<std::size_t> {static_cast<std::size_t>(selected_flow_index_)} : std::nullopt,
            flow_packet_index,
            loaded_packet_row_count_ > 0U ? std::optional<std::size_t> {loaded_packet_row_count_} : std::nullopt,
            payload_lengths.real_payload_length,
            payload_lengths.original_payload_length
        );
        packet_byte_presentation = session_detail::build_selected_packet_byte_presentation(
            *details,
            *packet,
            session_detail::SelectedPacketByteBuildOptions {
                .packet_bytes = std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
                .flow_packet_index = packet_summary_preparation.flow_packet_index,
                .packet_data = packet_summary_preparation.packet_data,
                .tls_initial_parser_context = packet_summary_preparation.tls_initial_parser_context,
                .reconstructed_tls_records = std::move(packet_summary_preparation.reconstructed_tls_records),
                .quic_presentation = std::move(packet_summary_preparation.quic_presentation),
            }
        );
    } else if (unrecognized_packets_selected_) {
        packet_byte_presentation = session_.derive_selected_packet_byte_presentation(*packet);
    }

    if (!packet_byte_presentation.has_value()) {
        packet_details_model_.clearPacketBytePresentation();
        selected_packet_byte_view_stable_id_.clear();
        return;
    }

    const auto byte_descriptors = session_detail::build_selected_packet_byte_view_descriptors(*packet_byte_presentation);
    const auto selected_view_id = resolve_selected_packet_byte_view_id(byte_descriptors, selected_packet_byte_view_stable_id_);
    if (!selected_view_id.has_value()) {
        packet_details_model_.clearPacketBytePresentation();
        selected_packet_byte_view_stable_id_.clear();
        return;
    }

    HexDumpService hex_dump_service {};
    const auto packet_byte_content = session_detail::format_selected_packet_byte_view_content(
        *packet_byte_presentation,
        *selected_view_id,
        std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
        hex_dump_service
    );
    if (!packet_byte_content.has_value()) {
        packet_details_model_.clearPacketBytePresentation();
        selected_packet_byte_view_stable_id_.clear();
        return;
    }

    selected_packet_byte_view_stable_id_ = QString::fromStdString(packet_byte_content->stable_id);
    packet_details_model_.setPacketBytePresentation(
        packet_byte_view_descriptors_to_variant_list(byte_descriptors),
        QString::fromStdString(packet_byte_content->stable_id),
        QString::fromStdString(packet_byte_content->label),
        true,
        QString::fromStdString(packet_byte_content->state),
        packet_byte_content->available_length,
        optional_length_variant(packet_byte_content->declared_length),
        packet_byte_view_status_text(
            QString::fromStdString(packet_byte_content->state),
            QString::fromStdString(packet_byte_content->assembly_kind),
            optional_length_variant(packet_byte_content->contributing_unit_count),
            packet_byte_content->contributing_unit_kind.has_value()
                ? QVariant(QString::fromStdString(*packet_byte_content->contributing_unit_kind))
                : QVariant {},
            packet_byte_content->available_length,
            optional_length_variant(packet_byte_content->declared_length)
        ),
        QString::fromStdString(packet_byte_content->formatted_text)
    );
}

void MainController::selectUnrecognizedPackets() {
    if (session_.unrecognized_packet_count() == 0U || unrecognized_packets_selected_) {
        return;
    }

    if (!analysis_sequence_export_in_progress_ && (!analysis_sequence_export_status_text_.isEmpty() || analysis_sequence_export_status_is_error_)) {
        setAnalysisSequenceExportState(false, {}, false);
    }

    selected_flow_index_ = -1;
    unrecognized_packets_selected_ = true;
    stream_tab_active_ = false;
    clearPacketSelection();
    clearStreamSelection();
    clearSelectedFlowAnalysis();
    current_flow_packet_numbers_.clear();
    current_suspected_retransmission_packet_indices_.clear();
    prepared_tcp_contribution_packet_window_count_ = 0U;
    session_.clear_selected_flow_packet_cache();
    session_.clear_selected_flow_tcp_payload_suppression();
    packet_model_.clear();
    current_stream_items_.clear();
    stream_model_.clear();
    total_packet_row_count_ = session_.unrecognized_packet_count();
    loaded_packet_row_count_ = 0U;
    packets_loading_ = true;
    stream_loading_ = false;
    loaded_stream_item_count_ = 0U;
    total_stream_item_count_ = 0U;
    stream_packet_window_count_ = 0U;
    stream_item_budget_count_ = 0U;
    can_load_more_stream_items_ = false;
    stream_state_materialized_for_selected_flow_ = false;

    emit selectedFlowIndexChanged();
    emit unrecognizedPacketsSelectionChanged();
    emit selectedFlowWiresharkFilterChanged();
    emit packetListStateChanged();
    emit streamListStateChanged();
    emit actionAvailabilityChanged();

    QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents, 5);
    refreshUnrecognizedPackets(true);
}

QString MainController::captureStorageSummaryText() const {
    if (!session_.has_capture()) {
        return QStringLiteral("No capture loaded.");
    }

    return formatCaptureStorageSummaryText(session_.storage_summary());
}

void MainController::setSelectedStreamItemIndex(const qulonglong streamItemIndex) {
    if (selected_stream_item_index_ == streamItemIndex) {
        return;
    }

    selected_stream_item_index_ = streamItemIndex;
    if (selected_stream_item_index_ == kInvalidStreamSelection) {
        if (details_selection_context_ == DetailsSelectionContext::stream) {
            details_selection_context_ = DetailsSelectionContext::none;
            packet_details_model_.clear();
        }
        emit selectedStreamItemIndexChanged();
        return;
    }

    details_selection_context_ = DetailsSelectionContext::stream;
    reloadSelectedStreamDetails();
    emit selectedStreamItemIndexChanged();
}

void MainController::setFlowFilterText(const QString& text) {
    if (simple_flow_filter_text_ == text) {
        return;
    }

    simple_flow_filter_text_ = text;
    if (flow_filter_mode_ == FlowFilterMode::simple) {
        flow_model_.setFilterText(simple_flow_filter_text_);
        synchronizeFlowSelection();
    }
    emit flowFilterTextChanged();
    emit smartExportCurrentFilterAvailableChanged();
}

void MainController::applyAdvancedFlowFilterDocument(const session_detail::AdvancedFlowFilterDocument& document) {
    advanced_flow_filter_document_state_.accept_custom_document(document);
    if (advanced_flow_filter_document_state_.is_editing()) {
        advanced_flow_filter_editor_model_.initializeFromCurrentDocument();
        refreshAdvancedFlowFilterProtocolPathApplicability();
    } else {
        advanced_flow_filter_editor_model_.clearTransientState();
    }
    refreshAdvancedFlowFilter();
    emit smartExportCurrentFilterAvailableChanged();
    emit advancedFlowFilterPresentationChanged();
}

bool MainController::ensureSourceCaptureAvailable(const QString& unavailableActionText) {
    if (!session_.has_capture()) {
        return false;
    }

    if (session_.has_source_capture() && !session_.source_capture_accessible()) {
        handleSourceCaptureUnavailable();
    }

    if (session_.has_source_capture()) {
        return true;
    }

    if (!unavailableActionText.isEmpty()) {
        setStatusText(unavailableActionText, true);
    }
    return false;
}

void MainController::handleSourceCaptureUnavailable() {
    if (!session_.has_source_capture()) {
        return;
    }

    session_.clear_source_capture_attachment();
    prepared_tcp_contribution_packet_window_count_ = 0U;
    current_suspected_retransmission_packet_indices_.clear();

    const bool streamSelectionChanged = selected_stream_item_index_ != kInvalidStreamSelection;
    selected_stream_item_index_ = kInvalidStreamSelection;

    const bool streamStateChanged = stream_loading_ || loaded_stream_item_count_ != 0U || total_stream_item_count_ != 0U ||
        stream_packet_window_count_ != 0U || stream_item_budget_count_ != 0U || can_load_more_stream_items_ || stream_state_materialized_for_selected_flow_ ||
        !current_stream_items_.empty() || stream_model_.rowCount() != 0;
    current_stream_items_.clear();
    stream_model_.clear();
    stream_loading_ = false;
    loaded_stream_item_count_ = 0U;
    total_stream_item_count_ = 0U;
    stream_packet_window_count_ = 0U;
    stream_item_budget_count_ = 0U;
    can_load_more_stream_items_ = false;
    stream_state_materialized_for_selected_flow_ = false;

    if (details_selection_context_ == DetailsSelectionContext::packet && selected_packet_index_ != kInvalidPacketSelection) {
        showSourceUnavailablePacketDetailsPlaceholder();
    } else if (stream_tab_active_ && selected_flow_index_ >= 0) {
        details_selection_context_ = DetailsSelectionContext::none;
        showSourceUnavailableStreamDetailsPlaceholder();
    }

    if (!source_capture_unavailable_notice_shown_) {
        setStatusText(source_capture_unavailable_status_text());
        source_capture_unavailable_notice_shown_ = true;
    }

    if (streamSelectionChanged) {
        emit selectedStreamItemIndexChanged();
    }
    if (streamStateChanged) {
        emit streamListStateChanged();
    }
    emit sourceAvailabilityChanged();
    emit actionAvailabilityChanged();
}

void MainController::showSourceUnavailablePacketDetailsPlaceholder() {
    packet_details_model_.setDetailsTitle(QStringLiteral("Packet Details"));
    packet_details_model_.clearStreamItemPresentation();
    packet_details_model_.setPacketDetailsText(source_capture_unavailable_packet_summary_text());
    packet_details_model_.setSummaryLayers({});
    packet_details_model_.setPacketBytePresentation(
        {},
        {},
        {},
        false,
        {},
        0U,
        {},
        QStringLiteral("Byte-backed packet details unavailable."),
        source_capture_unavailable_packet_raw_text()
    );
    packet_details_model_.setHexText({});
    packet_details_model_.clearStreamItemDataPresentation();
    packet_details_model_.setPayloadTabTitle(QStringLiteral("Payload"));
    packet_details_model_.setPayloadText({});
    selected_packet_byte_view_stable_id_.clear();
}

void MainController::showSourceUnavailableStreamDetailsPlaceholder() {
    packet_details_model_.setDetailsTitle(QStringLiteral("Stream Item Details"));
    packet_details_model_.clearStreamItemPresentation();
    packet_details_model_.setPacketDetailsText(source_capture_unavailable_stream_summary_text());
    packet_details_model_.setSummaryLayers({});
    packet_details_model_.clearPacketBytePresentation();
    packet_details_model_.setHexText({});
    packet_details_model_.setPayloadTabTitle(stream_item_data_tab_title());
    packet_details_model_.setPayloadText({});
    packet_details_model_.setStreamItemDataPresentation(
        false,
        {},
        QStringLiteral("unavailable"),
        QStringLiteral("unavailable"),
        {},
        0U,
        {},
        {},
        {},
        {},
        QStringLiteral("Item data unavailable • The original source capture cannot be read."),
        {}
    );
}

void MainController::prepareSelectedFlowTcpContributionState(const std::size_t maxPacketsToScan) {
    if (selected_flow_index_ < 0 || maxPacketsToScan == 0U) {
        current_suspected_retransmission_packet_indices_.clear();
        prepared_tcp_contribution_packet_window_count_ = 0U;
        session_.clear_selected_flow_packet_cache();
        session_.clear_selected_flow_tcp_payload_suppression();
        return;
    }

    if (prepared_tcp_contribution_packet_window_count_ >= maxPacketsToScan) {
        return;
    }

    if (!selected_flow_uses_tcp(flow_model_, selected_flow_index_)) {
        current_suspected_retransmission_packet_indices_.clear();
        session_.clear_selected_flow_tcp_payload_suppression();
        prepared_tcp_contribution_packet_window_count_ = maxPacketsToScan;
        return;
    }

    const auto flowIndex = static_cast<std::size_t>(selected_flow_index_);
    const auto suppressedPacketIndices = session_.suspected_tcp_retransmission_packet_indices(flowIndex, maxPacketsToScan);
    current_suspected_retransmission_packet_indices_.clear();
    for (const auto packetIndex : suppressedPacketIndices) {
        current_suspected_retransmission_packet_indices_.insert(packetIndex);
    }

    session_.set_selected_flow_tcp_payload_suppression(flowIndex, suppressedPacketIndices, maxPacketsToScan);
    prepared_tcp_contribution_packet_window_count_ = maxPacketsToScan;
}

void MainController::maybeEnrichSelectedFlowServiceHint() {
    if (selected_flow_index_ < 0 || !ensureSourceCaptureAvailable()) {
        return;
    }

    const auto row = flow_model_.rowForFlowIndex(selected_flow_index_);
    if (row < 0) {
        return;
    }

    const auto modelIndex = flow_model_.index(row, 0);
    const auto protocolHint = flow_model_.data(modelIndex, FlowListModel::ProtocolHintRole).toString();
    const auto serviceHint = flow_model_.data(modelIndex, FlowListModel::ServiceHintRole).toString();
    if (!serviceHint.isEmpty()) {
        return;
    }

    std::optional<std::string> derivedServiceHint {};
    if (protocolHint.compare(QStringLiteral("QUIC"), Qt::CaseInsensitive) == 0) {
        derivedServiceHint = session_.derive_quic_service_hint_for_flow(static_cast<std::size_t>(selected_flow_index_));
    } else if (protocolHint.compare(QStringLiteral("TLS"), Qt::CaseInsensitive) == 0 &&
               loaded_packet_row_count_ > 0U) {
        derivedServiceHint = session_detail::derive_tls_service_hint_for_loaded_flow_prefix(
            session_,
            static_cast<std::size_t>(selected_flow_index_),
            loaded_packet_row_count_
        );
    }

    if (!derivedServiceHint.has_value() || derivedServiceHint->empty()) {
        return;
    }

    flow_model_.setServiceHintForFlowIndex(selected_flow_index_, QString::fromStdString(*derivedServiceHint));
}

void MainController::ensureSelectedFlowPacketNumbers(const std::size_t packetWindowCount) {
    if (selected_flow_index_ < 0 || packetWindowCount == 0U) {
        return;
    }

    const auto knownCount = current_flow_packet_numbers_.size();
    if (knownCount >= packetWindowCount) {
        return;
    }

    const auto rows = session_.list_flow_packets(
        static_cast<std::size_t>(selected_flow_index_),
        knownCount,
        packetWindowCount - knownCount
    );
    for (const auto& packetRow : rows) {
        current_flow_packet_numbers_.insert_or_assign(packetRow.packet_index, packetRow.row_number);
    }
}

void MainController::refreshSelectedFlowPackets(const bool resetRows) {
    const bool previousLoading = packets_loading_;
    const auto previousLoaded = loaded_packet_row_count_;
    const auto previousTotal = total_packet_row_count_;

    if (selected_flow_index_ < 0) {
        packet_model_.clear();
        current_flow_packet_numbers_.clear();
        current_suspected_retransmission_packet_indices_.clear();
        session_.clear_selected_flow_packet_cache();
        session_.clear_selected_flow_tcp_payload_suppression();
        loaded_packet_row_count_ = 0U;
        total_packet_row_count_ = 0U;
        packets_loading_ = false;
        if (previousLoading != packets_loading_ || previousLoaded != loaded_packet_row_count_ || previousTotal != total_packet_row_count_) {
            emit packetListStateChanged();
        }
        return;
    }

    total_packet_row_count_ = session_.flow_packet_count(static_cast<std::size_t>(selected_flow_index_));
    const auto offset = resetRows ? std::size_t {0U} : loaded_packet_row_count_;
    const auto batchSize = resetRows
        ? std::min(kInitialPacketRows, total_packet_row_count_)
        : std::min(kPacketRowBatchSize, total_packet_row_count_ - offset);

    packets_loading_ = true;
    auto rows = session_.list_flow_packets(static_cast<std::size_t>(selected_flow_index_), offset, batchSize);

    if (resetRows) {
        current_suspected_retransmission_packet_indices_.clear();
        prepared_tcp_contribution_packet_window_count_ = 0U;
    }

    if (!rows.empty()) {
        session_.prepare_selected_flow_packet_cache(static_cast<std::size_t>(selected_flow_index_), offset + rows.size());
        prepareSelectedFlowTcpContributionState(offset + rows.size());
        apply_transient_packet_row_metadata(session_, static_cast<std::size_t>(selected_flow_index_), rows);
    }

    for (auto& packet_row : rows) {
        packet_row.suspected_tcp_retransmission = current_suspected_retransmission_packet_indices_.contains(packet_row.packet_index);
    }

    if (resetRows) {
        packet_model_.refresh(rows);
        current_flow_packet_numbers_.clear();
        loaded_packet_row_count_ = 0U;
    } else {
        packet_model_.append(rows);
    }

    for (const auto& packetRow : rows) {
        current_flow_packet_numbers_.insert_or_assign(packetRow.packet_index, packetRow.row_number);
    }

    loaded_packet_row_count_ = std::min(total_packet_row_count_, offset + rows.size());
    packets_loading_ = false;

    if (selected_packet_index_ != kInvalidPacketSelection && packet_model_.rowForPacketIndex(selected_packet_index_) < 0) {
        clearPacketSelection();
    }

    if (previousLoading != packets_loading_ || previousLoaded != loaded_packet_row_count_ || previousTotal != total_packet_row_count_) {
        emit packetListStateChanged();
    }

}

void MainController::refreshUnrecognizedPackets(const bool resetRows) {
    const bool previousLoading = packets_loading_;
    const auto previousLoaded = loaded_packet_row_count_;
    const auto previousTotal = total_packet_row_count_;

    if (!unrecognized_packets_selected_) {
        packet_model_.clear();
        loaded_packet_row_count_ = 0U;
        total_packet_row_count_ = 0U;
        packets_loading_ = false;
        if (previousLoading != packets_loading_ || previousLoaded != loaded_packet_row_count_ || previousTotal != total_packet_row_count_) {
            emit packetListStateChanged();
        }
        return;
    }

    total_packet_row_count_ = session_.unrecognized_packet_count();
    const auto offset = resetRows ? std::size_t {0U} : loaded_packet_row_count_;
    const auto batchSize = resetRows
        ? std::min(kInitialPacketRows, total_packet_row_count_)
        : std::min(kPacketRowBatchSize, total_packet_row_count_ - offset);

    packets_loading_ = true;
    const auto rows = session_.list_unrecognized_packets(offset, batchSize);

    if (resetRows) {
        packet_model_.refresh(rows);
        loaded_packet_row_count_ = 0U;
    } else {
        packet_model_.append(rows);
    }

    loaded_packet_row_count_ = std::min(total_packet_row_count_, offset + rows.size());
    packets_loading_ = false;

    if (selected_packet_index_ != kInvalidPacketSelection && packet_model_.rowForPacketIndex(selected_packet_index_) < 0) {
        clearPacketSelection();
    }

    if (previousLoading != packets_loading_ || previousLoaded != loaded_packet_row_count_ || previousTotal != total_packet_row_count_) {
        emit packetListStateChanged();
    }
}

void MainController::refreshSelectedStreamItems(const bool resetRows) {
    const bool previousLoading = stream_loading_;
    const auto previousLoaded = loaded_stream_item_count_;
    const auto previousTotal = total_stream_item_count_;
    const auto previousPacketWindow = stream_packet_window_count_;
    const auto previousCanLoadMore = can_load_more_stream_items_;

    if (selected_flow_index_ < 0) {
        current_stream_items_.clear();
        stream_model_.clear();
        stream_loading_ = false;
        loaded_stream_item_count_ = 0U;
        total_stream_item_count_ = 0U;
        stream_packet_window_count_ = 0U;
        stream_item_budget_count_ = 0U;
        can_load_more_stream_items_ = false;
        stream_state_materialized_for_selected_flow_ = false;
        if (previousLoading != stream_loading_
            || previousLoaded != loaded_stream_item_count_
            || previousTotal != total_stream_item_count_
            || previousPacketWindow != stream_packet_window_count_
            || previousCanLoadMore != can_load_more_stream_items_) {
            emit streamListStateChanged();
        }
        return;
    }

    if (!ensureSourceCaptureAvailable()) {
        current_stream_items_.clear();
        stream_model_.clear();
        stream_loading_ = false;
        loaded_stream_item_count_ = 0U;
        total_stream_item_count_ = 0U;
        stream_packet_window_count_ = 0U;
        stream_item_budget_count_ = 0U;
        can_load_more_stream_items_ = false;
        stream_state_materialized_for_selected_flow_ = false;
        if (previousLoading != stream_loading_
            || previousLoaded != loaded_stream_item_count_
            || previousTotal != total_stream_item_count_
            || previousPacketWindow != stream_packet_window_count_
            || previousCanLoadMore != can_load_more_stream_items_) {
            emit streamListStateChanged();
        }
        return;
    }

    const auto flowIndex = static_cast<std::size_t>(selected_flow_index_);
    const auto totalFlowPacketCount = session_.flow_packet_count(flowIndex);
    if (resetRows) {
        stream_packet_window_count_ = std::min(totalFlowPacketCount, kInitialStreamPacketBudget);
        session_.prepare_selected_flow_packet_cache(flowIndex, stream_packet_window_count_);
        stream_item_budget_count_ = totalFlowPacketCount <= kInitialStreamPacketBudget
            ? session_.flow_stream_item_count(flowIndex)
            : kInitialStreamItems;
    } else {
        stream_packet_window_count_ = std::min(totalFlowPacketCount, stream_packet_window_count_ + kStreamPacketBatchSize);
        stream_item_budget_count_ += kStreamItemBatchSize;
    }

    stream_loading_ = true;
    session_.prepare_selected_flow_packet_cache(flowIndex, stream_packet_window_count_);
    prepareSelectedFlowTcpContributionState(stream_packet_window_count_);
    ensureSelectedFlowPacketNumbers(stream_packet_window_count_);
    const auto requestLimit = stream_item_budget_count_ + 1U;
    const bool packetBudgetExhausted = stream_packet_window_count_ < totalFlowPacketCount;
    auto rows = session_.list_flow_stream_items_for_packet_prefix(
        flowIndex,
        stream_packet_window_count_,
        requestLimit
    );

    const bool hasMoreItems = rows.size() > stream_item_budget_count_;
    if (hasMoreItems) {
        rows.resize(stream_item_budget_count_);
    }

    current_stream_items_ = rows;
    stream_model_.refresh(current_stream_items_, current_flow_packet_numbers_);

    loaded_stream_item_count_ = current_stream_items_.size();
    can_load_more_stream_items_ = packetBudgetExhausted || hasMoreItems;
    total_stream_item_count_ = can_load_more_stream_items_ ? 0U : loaded_stream_item_count_;
    stream_loading_ = false;
    stream_state_materialized_for_selected_flow_ = true;

    if (selected_stream_item_index_ != kInvalidStreamSelection) {
        const auto selectedIt = std::find_if(current_stream_items_.begin(), current_stream_items_.end(), [&](const StreamItemRow& item) {
            return item.stream_item_index == static_cast<std::uint64_t>(selected_stream_item_index_);
        });
        if (selectedIt == current_stream_items_.end()) {
            clearStreamSelection();
        }
    }

    if (previousLoading != stream_loading_
        || previousLoaded != loaded_stream_item_count_
        || previousTotal != total_stream_item_count_
        || previousPacketWindow != stream_packet_window_count_
        || previousCanLoadMore != can_load_more_stream_items_) {
        emit streamListStateChanged();
    }

}

void MainController::refreshSelectedFlowAnalysis() {
    if (selected_flow_index_ < 0) {
        clearSelectedFlowAnalysis();
        return;
    }

    ++active_analysis_request_id_;
    const qulonglong requestId = active_analysis_request_id_;
    const int flowIndex = selected_flow_index_;
    const bool stateChanged = !analysis_loading_ || current_flow_analysis_.has_value();
    analysis_loading_ = true;
    current_flow_analysis_.reset();
    if (stateChanged) {
        emit analysisStateChanged();
    }

    QTimer::singleShot(0, this, [this, requestId, flowIndex]() {
        if (requestId != active_analysis_request_id_ || !analysis_tab_active_ || selected_flow_index_ != flowIndex) {
            return;
        }

        current_flow_analysis_ = session_.get_flow_analysis(static_cast<std::size_t>(flowIndex));
        analysis_loading_ = false;
        emit analysisStateChanged();
    });
}

void MainController::clearSelectedFlowAnalysis() {
    const bool hadState = analysis_loading_ || current_flow_analysis_.has_value();
    ++active_analysis_request_id_;
    analysis_loading_ = false;
    current_flow_analysis_.reset();
    if (hadState) {
        emit analysisStateChanged();
    }
}

void MainController::applyActiveFlowFilterModeToModel() {
    if (flow_filter_mode_ == FlowFilterMode::simple) {
        flow_model_.clearAdvancedFilterFlowIndices();
        flow_model_.setFilterText(simple_flow_filter_text_);
        if (status_is_error_ && is_advanced_filter_status_text(status_text_)) {
            setStatusText({}, false);
        }
        synchronizeFlowSelection();
        return;
    }

    flow_model_.setFilterText({});
    refreshAdvancedFlowFilter();
}

void MainController::refreshAdvancedFlowFilter() {
    if (flow_filter_mode_ != FlowFilterMode::advanced || !session_.has_capture()) {
        flow_model_.clearAdvancedFilterFlowIndices();
        if (status_is_error_ && is_advanced_filter_status_text(status_text_)) {
            setStatusText({}, false);
        }
        synchronizeFlowSelection();
        return;
    }

    const auto effective_spec = session_detail::make_effective_advanced_flow_filter_spec(
        advanced_flow_filter_document_state_.applied_document()
    );
    if (session_detail::count_advanced_flow_filter_atomic_rules(effective_spec) == 0U) {
        flow_model_.clearAdvancedFilterFlowIndices();
        if (status_is_error_ && is_advanced_filter_status_text(status_text_)) {
            setStatusText({}, false);
        }
        synchronizeFlowSelection();
        return;
    }

    std::optional<std::vector<std::size_t>> candidate_flow_indices {};
    if (has_active_protocol_path_filter_) {
        if (!build_protocol_path_candidate_flow_indices(
                active_protocol_path_filter_flow_indices_,
                candidate_flow_indices)) {
            flow_model_.clearAdvancedFilterFlowIndices();
            setStatusText(QStringLiteral("Advanced filter could not be applied because a candidate flow index is invalid."), true);
            synchronizeFlowSelection();
            return;
        }
    }

    const auto query_result = session_.query_advanced_flows(effective_spec, candidate_flow_indices, std::nullopt, std::nullopt);
    switch (query_result.status) {
    case session_detail::AdvancedFlowQueryStatus::ok: {
        std::vector<int> matching_flow_indices {};
        matching_flow_indices.reserve(query_result.ordered_flow_indices.size());
        for (const auto flow_index : query_result.ordered_flow_indices) {
            if (flow_index > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
                flow_model_.clearAdvancedFilterFlowIndices();
                setStatusText(QStringLiteral("Advanced filter produced a flow index that is out of range."), true);
                synchronizeFlowSelection();
                return;
            }
            matching_flow_indices.push_back(static_cast<int>(flow_index));
        }
        flow_model_.setAdvancedFilterFlowIndices(std::move(matching_flow_indices));
        if (status_is_error_ && is_advanced_filter_status_text(status_text_)) {
            setStatusText({}, false);
        }
        break;
    }
    case session_detail::AdvancedFlowQueryStatus::invalid_advanced_filter:
        flow_model_.clearAdvancedFilterFlowIndices();
        setStatusText(format_advanced_filter_application_error(query_result), true);
        break;
    case session_detail::AdvancedFlowQueryStatus::invalid_flow_index:
        flow_model_.clearAdvancedFilterFlowIndices();
        setStatusText(QStringLiteral("Advanced filter could not be applied because a candidate flow index is invalid."), true);
        break;
    case session_detail::AdvancedFlowQueryStatus::invalid_limit:
        flow_model_.clearAdvancedFilterFlowIndices();
        setStatusText(QStringLiteral("Advanced filter could not be applied because the limit is invalid."), true);
        break;
    }

    synchronizeFlowSelection();
}

void MainController::refreshAdvancedFlowFilterProtocolPathApplicability() {
    advanced_flow_filter_protocol_path_selector_model_.setCaptureSession(&session_);
    advanced_flow_filter_editor_model_.refreshProtocolPathApplicability();
}

std::vector<int> MainController::smartExportCurrentFilterFlowIndices(const bool matching) const {
    if (!smartExportCurrentFilterAvailable()) {
        return {};
    }

    std::optional<std::vector<std::size_t>> candidate_flow_indices {};
    std::vector<int> candidate_indices {};
    if (has_active_protocol_path_filter_) {
        if (!build_protocol_path_candidate_flow_indices(
                active_protocol_path_filter_flow_indices_,
                candidate_flow_indices,
                &candidate_indices)) {
            return {};
        }
    }

    std::vector<int> matching_flow_indices {};
    if (flow_filter_mode_ == FlowFilterMode::simple) {
        const auto flow_query_result = session_.query_flows(session_detail::FlowQuery {
            .selected_flow_indices = candidate_flow_indices,
            .text_filter = simple_flow_filter_text_.toStdString(),
            .sort = std::nullopt,
            .limit = std::nullopt,
        });
        if (flow_query_result.status != session_detail::FlowQueryStatus::ok) {
            return {};
        }

        matching_flow_indices.reserve(flow_query_result.ordered_flow_indices.size());
        for (const auto flow_index : flow_query_result.ordered_flow_indices) {
            if (flow_index > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
                return {};
            }
            matching_flow_indices.push_back(static_cast<int>(flow_index));
        }
    } else if (flow_filter_mode_ == FlowFilterMode::advanced) {
        const auto effective_spec = session_detail::make_effective_advanced_flow_filter_spec(
            advanced_flow_filter_document_state_.applied_document()
        );
        if (session_detail::count_advanced_flow_filter_atomic_rules(effective_spec) == 0U) {
            return {};
        }

        const auto query_result = session_.query_advanced_flows(
            effective_spec,
            candidate_flow_indices,
            std::nullopt,
            std::nullopt
        );
        if (query_result.status != session_detail::AdvancedFlowQueryStatus::ok) {
            return {};
        }

        matching_flow_indices.reserve(query_result.ordered_flow_indices.size());
        for (const auto flow_index : query_result.ordered_flow_indices) {
            if (flow_index > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
                return {};
            }
            matching_flow_indices.push_back(static_cast<int>(flow_index));
        }
    } else {
        return {};
    }

    if (matching) {
        return matching_flow_indices;
    }

    if (!has_active_protocol_path_filter_) {
        const auto rows = session_.list_flows();
        candidate_indices.reserve(rows.size());
        for (const auto& row : rows) {
            if (row.index > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
                return {};
            }
            candidate_indices.push_back(static_cast<int>(row.index));
        }
        std::sort(candidate_indices.begin(), candidate_indices.end());
        candidate_indices.erase(std::unique(candidate_indices.begin(), candidate_indices.end()), candidate_indices.end());
    }

    std::sort(matching_flow_indices.begin(), matching_flow_indices.end());
    matching_flow_indices.erase(std::unique(matching_flow_indices.begin(), matching_flow_indices.end()), matching_flow_indices.end());

    std::vector<int> hidden_flow_indices {};
    hidden_flow_indices.reserve(candidate_indices.size());
    std::set_difference(
        candidate_indices.begin(),
        candidate_indices.end(),
        matching_flow_indices.begin(),
        matching_flow_indices.end(),
        std::back_inserter(hidden_flow_indices)
    );
    return hidden_flow_indices;
}

void MainController::clearPacketSelection() {
    const bool selectionChanged = selected_packet_index_ != kInvalidPacketSelection;
    const bool wasActive = details_selection_context_ == DetailsSelectionContext::packet;
    selected_packet_byte_view_stable_id_.clear();
    selected_packet_index_ = kInvalidPacketSelection;

    if (wasActive) {
        details_selection_context_ = DetailsSelectionContext::none;
        packet_details_model_.clear();
    }

    if (selectionChanged) {
        emit selectedPacketIndexChanged();
    }
}

void MainController::clearStreamSelection() {
    const bool selectionChanged = selected_stream_item_index_ != kInvalidStreamSelection;
    const bool wasActive = details_selection_context_ == DetailsSelectionContext::stream;
    selected_stream_item_index_ = kInvalidStreamSelection;

    if (wasActive) {
        details_selection_context_ = DetailsSelectionContext::none;
        packet_details_model_.clear();
    }

    if (selectionChanged) {
        emit selectedStreamItemIndexChanged();
    }
}

void MainController::clearFlowSelection() {
    const bool flowChanged = selected_flow_index_ != -1;
    const bool unrecognizedSelectionChanged = unrecognized_packets_selected_;
    const bool packetStateChanged = packets_loading_ || loaded_packet_row_count_ != 0U || total_packet_row_count_ != 0U;
    const bool streamStateChanged = stream_loading_ || loaded_stream_item_count_ != 0U || total_stream_item_count_ != 0U || stream_packet_window_count_ != 0U || stream_item_budget_count_ != 0U || can_load_more_stream_items_ || stream_state_materialized_for_selected_flow_;
    selected_flow_index_ = -1;
    unrecognized_packets_selected_ = false;
    packet_model_.clear();
    current_stream_items_.clear();
    current_flow_packet_numbers_.clear();
    current_suspected_retransmission_packet_indices_.clear();
    session_.clear_selected_flow_packet_cache();
    session_.clear_selected_flow_tcp_payload_suppression();
    stream_model_.clear();
    loaded_packet_row_count_ = 0U;
    total_packet_row_count_ = 0U;
    packets_loading_ = false;
    loaded_stream_item_count_ = 0U;
    total_stream_item_count_ = 0U;
    stream_packet_window_count_ = 0U;
    stream_item_budget_count_ = 0U;
    stream_loading_ = false;
    can_load_more_stream_items_ = false;
    stream_state_materialized_for_selected_flow_ = false;
    clearPacketSelection();
    clearStreamSelection();
    clearSelectedFlowAnalysis();
    if (!analysis_sequence_export_in_progress_ && (!analysis_sequence_export_status_text_.isEmpty() || analysis_sequence_export_status_is_error_)) {
        setAnalysisSequenceExportState(false, {}, false);
    }

    if (packetStateChanged) {
        emit packetListStateChanged();
    }
    if (streamStateChanged) {
        emit streamListStateChanged();
    }

    if (flowChanged) {
        emit selectedFlowIndexChanged();
    }
    if (unrecognizedSelectionChanged) {
        emit unrecognizedPacketsSelectionChanged();
    }
    if (flowChanged || unrecognizedSelectionChanged) {
        emit selectedFlowWiresharkFilterChanged();
        emit actionAvailabilityChanged();
    }
}

void MainController::synchronizeFlowSelection() {
    if (selected_flow_index_ >= 0 && !flow_model_.containsFlowIndex(selected_flow_index_)) {
        clearFlowSelection();
    }
}

bool MainController::clearProtocolPathFlowFilterState() {
    const bool changed = has_active_protocol_path_filter_ ||
        active_protocol_path_filter_node_id_ != kInvalidProtocolPathStatisticsNodeId ||
        !active_protocol_path_filter_label_.isEmpty() ||
        !active_protocol_path_filter_flow_indices_.empty();

    has_active_protocol_path_filter_ = false;
    active_protocol_path_filter_mode_ = ProtocolPathStatisticsMode::kind_overview;
    active_protocol_path_filter_node_id_ = kInvalidProtocolPathStatisticsNodeId;
    active_protocol_path_filter_label_.clear();
    active_protocol_path_filter_flow_indices_.clear();
    flow_model_.clearAllowedFlowIndices();
    return changed;
}

void MainController::resetLoadedState() {
    setApplyingSession(false);
    source_capture_unavailable_notice_shown_ = false;
    current_input_path_.clear();
    finishOpenProgress();
    session_ = {};
    advanced_flow_filter_protocol_path_selector_model_.setCaptureSession(&session_);
    protocol_summary_ = {};
    unrecognized_packet_statistics_ = {};
    whole_capture_packet_count_ = 0U;
    whole_capture_captured_bytes_ = 0U;
    whole_capture_original_bytes_ = 0U;
    capture_time_statistics_.clear();
    capture_metrics_.clear();
    flow_characteristics_.clear();
    packet_direction_distribution_.clear();
    data_direction_distribution_.clear();
    statistics_partial_open_warning_text_.clear();
    resetStatisticsSectionState(true);
    clearProtocolPathFlowFilterState();
    flow_model_.clear();
    flow_model_.resetViewState();
    applyActiveFlowFilterModeToModel();
    packet_model_.clear();
    current_stream_items_.clear();
    current_flow_packet_numbers_.clear();
    current_suspected_retransmission_packet_indices_.clear();
    session_.clear_selected_flow_packet_cache();
    session_.clear_selected_flow_tcp_payload_suppression();
    stream_model_.clear();
    loaded_stream_item_count_ = 0U;
    total_stream_item_count_ = 0U;
    stream_packet_window_count_ = 0U;
    stream_item_budget_count_ = 0U;
    stream_loading_ = false;
    can_load_more_stream_items_ = false;
    stream_state_materialized_for_selected_flow_ = false;
    packets_loading_ = false;
    loaded_packet_row_count_ = 0U;
    total_packet_row_count_ = 0U;
    packet_details_model_.clear();
    top_endpoints_model_.clear();
    top_ports_model_.clear();
    selected_flow_index_ = -1;
    unrecognized_packets_selected_ = false;
    selected_packet_index_ = kInvalidPacketSelection;
    selected_stream_item_index_ = kInvalidStreamSelection;
    details_selection_context_ = DetailsSelectionContext::none;
    ++active_analysis_request_id_;
    analysis_loading_ = false;
    emit analysisStateChanged();
    current_flow_analysis_.reset();
    setAnalysisSequenceExportState(false, {}, false);
    emit protocolPathFlowFilterChanged();
    refreshAdvancedFlowFilterProtocolPathApplicability();
}

void MainController::applyLoadedState(const QString& path) {
    source_capture_unavailable_notice_shown_ = false;
    current_input_path_ = path;
    advanced_flow_filter_protocol_path_selector_model_.setCaptureSession(&session_);
    protocol_summary_ = session_.protocol_summary();
    const auto& whole_capture_packet_statistics = session_.packet_statistics();
    unrecognized_packet_statistics_ = session_.unrecognized_packet_statistics();
    whole_capture_packet_count_ = whole_capture_packet_statistics.total_packet_count;
    whole_capture_captured_bytes_ = whole_capture_packet_statistics.total_captured_bytes;
    whole_capture_original_bytes_ = whole_capture_packet_statistics.total_original_bytes;
    refreshStatisticsOverviewPresentation();
    resetStatisticsSectionState(true);
    clearProtocolPathFlowFilterState();
    // Clear any selected-flow state from the previous capture before publishing
    // the new flow list, so re-selecting flow 0 after a reload always refreshes.
    clearFlowSelection();
    flow_model_.clear();
    flow_model_.resetViewState();
    flow_model_.refresh(session_.list_flows());
    applyActiveFlowFilterModeToModel();
    setOpenErrorText({});
    setStatusText({});
    if (current_tab_index_ == kStatsTabIndex) {
        maybeLoadExpandedStatisticsSections();
    }
    emit stateChanged();
    emit sourceAvailabilityChanged();
    emit actionAvailabilityChanged();
    emit protocolPathFlowFilterChanged();
    refreshAdvancedFlowFilterProtocolPathApplicability();
}

void MainController::refreshTopSummaryModels() {
    if (session_.summary().flow_count <= 30U) {
        top_endpoints_model_.refreshEndpoints({});
        top_ports_model_.refreshPorts({});
        return;
    }

    const auto top = session_.top_summary(kTopSummaryLimit);
    top_endpoints_model_.refreshEndpoints(top.endpoints_by_bytes);
    top_ports_model_.refreshPorts(top.ports_by_bytes);
}

void MainController::refreshStatisticsOverviewPresentation() {
    if (!session_.has_capture()) {
        capture_time_statistics_.clear();
        capture_metrics_.clear();
        flow_characteristics_.clear();
        packet_direction_distribution_.clear();
        data_direction_distribution_.clear();
        statistics_partial_open_warning_text_.clear();
        return;
    }

    const auto& packet_statistics = session_.packet_statistics();
    const auto flow_characteristics_statistics = session_.flow_characteristics_statistics();
    const auto packet_direction_distribution_statistics = session_.packet_direction_distribution_statistics();
    const auto original_byte_direction_distribution_statistics =
        session_.original_byte_direction_distribution_statistics();
    capture_time_statistics_ = capture_time_statistics_to_variant_map(
        build_frontend_capture_time_statistics(packet_statistics)
    );
    capture_metrics_ = capture_metrics_to_variant_map(
        build_frontend_capture_metrics(packet_statistics)
    );
    flow_characteristics_ = flow_characteristics_to_variant_map(
        build_frontend_flow_characteristics(flow_characteristics_statistics)
    );
    packet_direction_distribution_ = direction_distribution_to_variant_map(
        build_frontend_packet_direction_distribution(
            flow_characteristics_statistics,
            packet_direction_distribution_statistics
        )
    );
    data_direction_distribution_ = direction_distribution_to_variant_map(
        build_frontend_original_byte_direction_distribution(
            flow_characteristics_statistics,
            original_byte_direction_distribution_statistics
        )
    );
    statistics_partial_open_warning_text_ = QString::fromStdString(
        build_frontend_statistics_partial_open_warning_text(session_.is_partial_open())
    );
}

bool MainController::openPath(const QString& path, const bool asIndex) {
    const QString trimmedPath = path.trimmed();
    if (trimmedPath.isEmpty()) {
        setOpenErrorText(QStringLiteral("No file selected."));
        return false;
    }

    if (is_opening_ || open_thread_ != nullptr) {
        setStatusText(QStringLiteral("Another open request is already in progress."), true);
        return false;
    }

    if (flow_info_csv_export_in_progress_ || flow_info_csv_export_thread_ != nullptr) {
        setStatusText(QStringLiteral("Wait for the current flow info CSV export to finish before opening another session."), true);
        return false;
    }

    setOpenErrorText({});
    setStatusText({});
    active_open_input_path_ = trimmedPath;
    active_open_as_index_ = asIndex;
    beginOpenProgress();

    const auto filesystemPath = std::filesystem::path {trimmedPath.toStdWString()};
    setLastDirectoryFromPath(filesystemPath);

    ++active_open_job_id_;
    const qulonglong jobId = active_open_job_id_;
    const CaptureImportOptions importOptions {
        .settings = pending_analysis_settings_,
    };
    active_open_context_ = std::make_shared<OpenContext>();
    active_open_context_->on_progress = [this, jobId](const OpenProgress& progress) {
        QMetaObject::invokeMethod(this, [this, jobId, progress]() {
            if (active_open_job_id_ != jobId || !is_opening_) {
                return;
            }

            updateOpenProgress(progress);
        }, Qt::QueuedConnection);
    };

    const auto context = active_open_context_;
    open_thread_ = QThread::create([this, jobId, trimmedPath, filesystemPath, asIndex, importOptions, context]() mutable {
        OpenJobResult result {};
        result.as_index = asIndex;
        result.input_path = trimmedPath;

        CaptureSession workerSession {};
        if (asIndex) {
            result.opened = workerSession.load_index(filesystemPath, context.get());
        } else {
            result.opened = workerSession.open_capture(filesystemPath, importOptions, context.get());
        }

        result.cancelled = context->is_cancel_requested();
        result.error_text = QString::fromStdString(workerSession.last_open_error_text());
        if (result.opened && !result.cancelled) {
            result.session = std::move(workerSession);
        }

        QMetaObject::invokeMethod(this, [this, jobId, result = std::move(result)]() mutable {
            completeOpenJob(jobId, result.input_path, result.as_index, result.opened, result.cancelled, result.error_text, std::move(result.session));
        }, Qt::QueuedConnection);
    });

    QObject::connect(open_thread_, &QThread::finished, open_thread_, &QObject::deleteLater);
    open_thread_->start();
    return true;
}

void MainController::completeOpenJob(
    const qulonglong jobId,
    const QString& path,
    const bool asIndex,
    const bool opened,
    const bool cancelled,
    const QString& errorText,
    CaptureSession session
) {
    if (jobId != active_open_job_id_) {
        return;
    }

    const bool cancellationWon = cancelled || (active_open_context_ != nullptr && active_open_context_->is_cancel_requested());
    active_open_job_id_ = 0;
    cleanupOpenThread();
    releaseOpenContext();

    if (cancellationWon) {
        if (clearProtocolPathFlowFilterState()) {
            synchronizeFlowSelection();
            emit protocolPathFlowFilterChanged();
        }
        finishOpenProgress();
        setOpenErrorText({});
        setStatusText(QStringLiteral("Open cancelled."));
        return;
    }

    if (!opened) {
        if (clearProtocolPathFlowFilterState()) {
            synchronizeFlowSelection();
            emit protocolPathFlowFilterChanged();
        }
        finishOpenProgress();
        const QString genericError = asIndex
            ? QStringLiteral("Failed to open analysis index.")
            : QStringLiteral("Failed to open capture file.");
        setOpenErrorText(genericError);
        setStatusText(errorText.isEmpty() ? genericError : errorText, true);
        return;
    }

    const auto loadedSession = std::make_shared<CaptureSession>(std::move(session));
    setApplyingSession(true);
    QTimer::singleShot(kSessionApplyOverlayDelayMs, this, [this, path, loadedSession]() mutable {
        session_ = std::move(*loadedSession);
        session_.clear_runtime_caches_after_transfer();
        applyLoadedState(path);
        setApplyingSession(false);
        finishOpenProgress();
    });
}

void MainController::completeAnalysisSequenceExport(
    const qulonglong jobId,
    const QString& outputPath,
    const bool exported,
    const QString& errorText
) {
    if (jobId != active_analysis_sequence_export_job_id_) {
        return;
    }

    active_analysis_sequence_export_job_id_ = 0;
    cleanupAnalysisSequenceExportThread();

    if (!exported) {
        const auto message = errorText.isEmpty()
            ? QStringLiteral("Failed to export flow sequence CSV.")
            : errorText;
        setAnalysisSequenceExportState(false, message, true);
        return;
    }

    setAnalysisSequenceExportState(false, QStringLiteral("Flow sequence CSV exported: %1").arg(outputPath), false);
}

void MainController::completeFlowInfoCsvExport(
    const qulonglong jobId,
    const QString& outputPath,
    const bool exported,
    const QString& errorText
) {
    if (jobId != active_flow_info_csv_export_job_id_) {
        return;
    }

    active_flow_info_csv_export_job_id_ = 0;
    flow_info_csv_export_in_progress_ = false;
    cleanupFlowInfoExportThread();
    emit actionAvailabilityChanged();

    if (!exported) {
        setStatusText(
            errorText.isEmpty()
                ? QStringLiteral("Failed to export flow info CSV.")
                : errorText,
            true
        );
        return;
    }

    setStatusText(QStringLiteral("Flow info CSV exported: %1").arg(outputPath));
}

void MainController::updateIndexSaveProgress(const qulonglong jobId, const IndexSaveProgress& progress) {
    if (jobId != active_index_save_job_id_) {
        return;
    }

    const auto section_total_text = QString::number(progress.total_sections);
    const auto completed_text = QString::number(progress.completed_sections);
    QString progress_text = QString::fromStdString(progress.phase_text);
    if (progress.total_sections > 0U) {
        progress_text += QStringLiteral(" (%1 / %2 sections)")
            .arg(completed_text, section_total_text);
    }
    if (progress.phase_items_total > 0U) {
        progress_text += QStringLiteral(" [%1 / %2 items]")
            .arg(QString::number(progress.phase_items_processed), QString::number(progress.phase_items_total));
    }

    double progress_percent {0.0};
    if (progress.total_sections > 0U) {
        const auto completed_sections = std::min(progress.completed_sections, progress.total_sections);
        if (completed_sections >= progress.total_sections) {
            progress_percent = 1.0;
        } else {
            const auto current_fraction =
                progress.phase_items_total > 0U
                    ? std::clamp(
                          static_cast<double>(std::min(progress.phase_items_processed, progress.phase_items_total)) /
                              static_cast<double>(progress.phase_items_total),
                          0.0,
                          1.0
                      )
                    : 0.0;
            progress_percent = std::clamp(
                (static_cast<double>(completed_sections) + current_fraction) /
                    static_cast<double>(progress.total_sections),
                0.0,
                1.0
            );
        }
    }

    setIndexSaveState(
        true,
        index_save_cancel_requested_,
        progress_percent,
        index_save_cancel_requested_ ? progress_text + QStringLiteral(" Cancelling...") : progress_text
    );
}

void MainController::completeIndexSave(
    const qulonglong jobId,
    const QString& outputPath,
    const bool saved,
    const QString& errorText
) {
    if (jobId != active_index_save_job_id_) {
        return;
    }

    active_index_save_job_id_ = 0;
    index_save_cancel_token_.reset();
    const bool had_cancel_request = index_save_cancel_requested_;
    index_save_cancel_requested_ = false;
    cleanupIndexSaveThread();
    setIndexSaveState(false, false, 0.0, {});

    if (saved) {
        setStatusText(QStringLiteral("Analysis index saved successfully: %1").arg(outputPath));
        return;
    }

    if (had_cancel_request) {
        setStatusText(QStringLiteral("Analysis index save cancelled."));
        return;
    }

    const auto message = errorText.isEmpty()
        ? QStringLiteral("Failed to save analysis index.")
        : errorText;
    setStatusText(message, true);
}

void MainController::updateSmartExportProgress(
    const qulonglong jobId,
    const SmartPerFlowExportPhase phase,
    const qulonglong packetsProcessed,
    const qulonglong totalPackets,
    const qulonglong exportedPacketsWritten,
    const qulonglong totalSelectedPackets
) {
    if (jobId != active_smart_export_job_id_) {
        return;
    }

    const auto total_text = totalPackets > 0U ? QString::number(totalPackets) : QStringLiteral("...");
    QString progress_text {};
    switch (phase) {
    case SmartPerFlowExportPhase::preparing:
        progress_text = QStringLiteral("Preparing export: flow %1 / %2")
            .arg(QString::number(packetsProcessed), total_text);
        break;
    case SmartPerFlowExportPhase::writing:
        if (totalSelectedPackets > 0U) {
            progress_text = QStringLiteral("Writing output: scanned %1 / %2 packets; wrote %3 / %4 selected packets.")
                .arg(QString::number(packetsProcessed),
                     total_text,
                     QString::number(exportedPacketsWritten),
                     QString::number(totalSelectedPackets));
        } else {
            progress_text = QStringLiteral("Writing output: %1 / %2 packets.")
                .arg(QString::number(packetsProcessed), total_text);
            if (exportedPacketsWritten > 0U) {
                progress_text += QStringLiteral(" Wrote %1 packets.").arg(QString::number(exportedPacketsWritten));
            }
        }
        break;
    }
    setSmartExportState(
        true,
        packetsProcessed,
        totalPackets,
        smart_export_cancel_requested_ ? progress_text + QStringLiteral(" Cancelling...") : progress_text
    );
}

void MainController::completeSmartExport(
    const qulonglong jobId,
    const QString& successText,
    const QString& defaultFailureText,
    const bool exported,
    const bool cancelled,
    const QString& errorText
) {
    if (jobId != active_smart_export_job_id_) {
        return;
    }

    active_smart_export_job_id_ = 0;
    smart_export_cancel_token_.reset();
    const bool had_cancel_request = smart_export_cancel_requested_;
    smart_export_cancel_requested_ = false;
    cleanupSmartExportThread();
    setSmartExportState(false, 0U, 0U, {});

    if (exported) {
        setStatusText(successText);
        return;
    }

    if (cancelled || had_cancel_request) {
        setStatusText(QStringLiteral("Smart export cancelled."));
        return;
    }

    const auto message = errorText.isEmpty()
        ? defaultFailureText
        : errorText;
    setStatusText(message, true);
}

void MainController::cancelSmartExport() {
    if (!smart_export_in_progress_ || smart_export_cancel_requested_) {
        return;
    }

    smart_export_cancel_requested_ = true;
    if (smart_export_cancel_token_ != nullptr) {
        smart_export_cancel_token_->store(true, std::memory_order_relaxed);
    }
    const auto cancelling_text = smart_export_progress_text_.isEmpty()
        ? QStringLiteral("Cancelling smart export...")
        : smart_export_progress_text_ + QStringLiteral(" Cancelling...");
    setSmartExportState(
        true,
        smart_export_progress_packets_,
        smart_export_progress_total_packets_,
        cancelling_text
    );
    setStatusText(QStringLiteral("Cancelling smart export..."));
}

void MainController::cleanupAnalysisSequenceExportThread() {
    if (analysis_sequence_export_thread_ == nullptr) {
        return;
    }

    if (analysis_sequence_export_thread_->isRunning()) {
        analysis_sequence_export_thread_->wait();
    }

    analysis_sequence_export_thread_ = nullptr;
}

void MainController::cleanupFlowInfoExportThread() {
    if (flow_info_csv_export_thread_ == nullptr) {
        return;
    }

    if (flow_info_csv_export_thread_->isRunning()) {
        flow_info_csv_export_thread_->wait();
    }

    flow_info_csv_export_thread_ = nullptr;
}

void MainController::cleanupIndexSaveThread() {
    if (index_save_thread_ == nullptr) {
        return;
    }

    if (index_save_thread_->isRunning()) {
        index_save_thread_->wait();
    }

    index_save_thread_ = nullptr;
}

void MainController::cleanupSmartExportThread() {
    if (smart_export_thread_ == nullptr) {
        return;
    }

    if (smart_export_thread_->isRunning()) {
        smart_export_thread_->wait();
    }

    smart_export_thread_ = nullptr;
}

void MainController::cleanupOpenThread() {
    if (open_thread_ == nullptr) {
        return;
    }

    if (open_thread_->isRunning()) {
        open_thread_->wait();
    }

    open_thread_ = nullptr;
}

void MainController::releaseOpenContext() {
    active_open_context_.reset();
}

void MainController::reloadSelectedPacketDetails() {
    if (selected_packet_index_ == kInvalidPacketSelection) {
        return;
    }

    packet_details_model_.setDetailsTitle(QStringLiteral("Packet Details"));
    packet_details_model_.clearStreamItemPresentation();

    const auto packet = session_.find_packet(static_cast<std::uint64_t>(selected_packet_index_));
    if (!packet.has_value()) {
        packet_details_model_.clear();
        return;
    }

    if (!ensureSourceCaptureAvailable()) {
        showSourceUnavailablePacketDetailsPlaceholder();
        return;
    }

    const auto details = session_.read_packet_details(*packet);
    const auto packetBytes = session_.read_packet_data(*packet);
    const auto unrecognized_reason_text = [&]() -> QString {
        if (!unrecognized_packets_selected_) {
            return {};
        }

        const auto row = packet_model_.rowForPacketIndex(selected_packet_index_);
        if (row < 0) {
            return {};
        }

        return packet_model_.data(packet_model_.index(row, 0), PacketListModel::ReasonTextRole).toString();
    }();
    PacketChecksumSections checksum_sections {};
    if (details.has_value() && validate_selected_packet_checksums_) {
        checksum_sections = build_packet_checksum_sections(
            *details,
            *packet,
            std::span<const std::uint8_t>(packetBytes.data(), packetBytes.size())
        );
    }

    packet_details_model_.setHexText({});

    std::optional<session_detail::SelectedPacketSummaryPreparation> packet_summary_preparation {};

    if (details.has_value()) {
        const auto payload_lengths = resolve_transport_payload_lengths(
            *details,
            std::span<const std::uint8_t>(packetBytes.data(), packetBytes.size()),
            *packet
        );
        const auto flow_packet_index = [&]() -> std::optional<std::uint64_t> {
            const auto it = current_flow_packet_numbers_.find(packet->packet_index);
            if (it == current_flow_packet_numbers_.end() || it->second == 0U) {
                return std::nullopt;
            }
            return it->second - 1U;
        }();
        packet_summary_preparation = session_detail::prepare_selected_packet_summary(
            session_,
            *details,
            *packet,
            selected_flow_index_ >= 0 ? std::optional<std::size_t> {static_cast<std::size_t>(selected_flow_index_)} : std::nullopt,
            flow_packet_index,
            loaded_packet_row_count_ > 0U ? std::optional<std::size_t> {loaded_packet_row_count_} : std::nullopt,
            payload_lengths.real_payload_length,
            payload_lengths.original_payload_length,
            [&]() {
                std::vector<std::string> lines {};
                lines.reserve(static_cast<std::size_t>(checksum_sections.summary_lines.size()));
                for (const auto& line : checksum_sections.summary_lines) {
                    lines.push_back(line.toStdString());
                }
                return lines;
            }(),
            [&]() {
                std::vector<std::string> lines {};
                lines.reserve(static_cast<std::size_t>(checksum_sections.warnings.size()));
                for (const auto& line : checksum_sections.warnings) {
                    lines.push_back(line.toStdString());
                }
                return lines;
            }()
        );
        packet_details_model_.setPacketDetailsText(buildPacketSummary(*details, *packet, checksum_sections, payload_lengths));
        packet_details_model_.setSummaryLayers(packet_summary_layers_to_variant_list(
            session_detail::build_packet_summary_layers(*details, *packet, packet_summary_preparation->make_options())
        ));
    } else {
        const auto metadata = session_detail::derive_transient_packet_metadata(
            std::span<const std::uint8_t>(packetBytes.data(), packetBytes.size()),
            *packet
        );
        packet_details_model_.setPacketDetailsText(buildPacketSummaryFallback(
            *packet,
            unrecognized_reason_text,
            checksum_sections,
            metadata.is_ip_fragmented
        ));
        packet_details_model_.setSummaryLayers(packet_summary_layers_to_variant_list(
            build_packet_summary_fallback_layers(
                *packet,
                unrecognized_reason_text,
                checksum_sections,
                metadata.is_ip_fragmented
            )
        ));
    }

    std::optional<session_detail::SelectedPacketBytePresentation> packet_byte_presentation {};
    if (details.has_value() && packet_summary_preparation.has_value()) {
        packet_byte_presentation = session_detail::build_selected_packet_byte_presentation(
            *details,
            *packet,
            session_detail::SelectedPacketByteBuildOptions {
                .packet_bytes = std::span<const std::uint8_t>(packetBytes.data(), packetBytes.size()),
                .flow_packet_index = packet_summary_preparation->flow_packet_index,
                .packet_data = packet_summary_preparation->packet_data,
                .tls_initial_parser_context = packet_summary_preparation->tls_initial_parser_context,
                .reconstructed_tls_records = std::move(packet_summary_preparation->reconstructed_tls_records),
                .quic_presentation = std::move(packet_summary_preparation->quic_presentation),
            }
        );
    } else if (unrecognized_packets_selected_) {
        packet_byte_presentation = session_.derive_selected_packet_byte_presentation(*packet);
    }

    if (packet_byte_presentation.has_value()) {
        const auto byte_descriptors = session_detail::build_selected_packet_byte_view_descriptors(*packet_byte_presentation);
        const auto selected_view_id = resolve_selected_packet_byte_view_id(byte_descriptors, selected_packet_byte_view_stable_id_);
        if (selected_view_id.has_value()) {
            HexDumpService hex_dump_service {};
            if (const auto packet_byte_content = session_detail::format_selected_packet_byte_view_content(
                    *packet_byte_presentation,
                    *selected_view_id,
                    std::span<const std::uint8_t>(packetBytes.data(), packetBytes.size()),
                    hex_dump_service);
                packet_byte_content.has_value()) {
                selected_packet_byte_view_stable_id_ = QString::fromStdString(packet_byte_content->stable_id);
                packet_details_model_.setPacketBytePresentation(
                    packet_byte_view_descriptors_to_variant_list(byte_descriptors),
                    QString::fromStdString(packet_byte_content->stable_id),
                    QString::fromStdString(packet_byte_content->label),
                    true,
                    QString::fromStdString(packet_byte_content->state),
                    packet_byte_content->available_length,
                    optional_length_variant(packet_byte_content->declared_length),
                    packet_byte_view_status_text(
                        QString::fromStdString(packet_byte_content->state),
                        QString::fromStdString(packet_byte_content->assembly_kind),
                        optional_length_variant(packet_byte_content->contributing_unit_count),
                        packet_byte_content->contributing_unit_kind.has_value()
                            ? QVariant(QString::fromStdString(*packet_byte_content->contributing_unit_kind))
                            : QVariant {},
                        packet_byte_content->available_length,
                        optional_length_variant(packet_byte_content->declared_length)
                    ),
                    QString::fromStdString(packet_byte_content->formatted_text)
                );
            } else {
                packet_details_model_.clearPacketBytePresentation();
                selected_packet_byte_view_stable_id_.clear();
            }
        } else {
            packet_details_model_.clearPacketBytePresentation();
            selected_packet_byte_view_stable_id_.clear();
        }
    } else {
        packet_details_model_.clearPacketBytePresentation();
        selected_packet_byte_view_stable_id_.clear();
    }

    packet_details_model_.clearStreamItemDataPresentation();
    packet_details_model_.setPayloadTabTitle(QStringLiteral("Payload"));
    packet_details_model_.setPayloadText({});
}

void MainController::reloadSelectedStreamDetails() {
    if (selected_stream_item_index_ == kInvalidStreamSelection) {
        return;
    }

    if (!ensureSourceCaptureAvailable()) {
        showSourceUnavailableStreamDetailsPlaceholder();
        return;
    }

    const auto itemIt = std::find_if(current_stream_items_.begin(), current_stream_items_.end(), [&](const StreamItemRow& item) {
        return item.stream_item_index == static_cast<std::uint64_t>(selected_stream_item_index_);
    });
    if (itemIt == current_stream_items_.end()) {
        packet_details_model_.clear();
        return;
    }

    packet_details_model_.setDetailsTitle(QStringLiteral("Stream Item Details"));
    packet_details_model_.setStreamItemPresentation(
        stream_item_header_primary_text(*itemIt),
        stream_item_header_secondary_text(*itemIt, current_flow_packet_numbers_),
        stream_item_header_badge_text(*itemIt)
    );
    packet_details_model_.setPacketDetailsText(buildStreamItemSummary(*itemIt, current_flow_packet_numbers_));
    packet_details_model_.setSummaryLayers(packet_summary_layers_to_variant_list(
        session_detail::build_stream_item_summary_layers(
            *itemIt,
            format_stream_source_packets(*itemIt, current_flow_packet_numbers_).toStdString()
        )
    ));
    packet_details_model_.clearPacketBytePresentation();
    packet_details_model_.setHexText({});
    packet_details_model_.setPayloadTabTitle(stream_item_data_tab_title());
    packet_details_model_.clearStreamItemDataPresentation();

    const auto flow_index = static_cast<std::size_t>(selected_flow_index_);
    const auto packet_window_count = stream_packet_window_count_;
    const auto item_limit = loaded_stream_item_count_ > 0U
        ? loaded_stream_item_count_
        : current_stream_items_.size();
    const auto presentation = session_.derive_selected_flow_stream_item_data(
        flow_index,
        packet_window_count,
        item_limit,
        itemIt->stream_item_index
    );
    const auto formatted_text = session_.format_selected_flow_stream_item_data_hex_dump(
        flow_index,
        packet_window_count,
        item_limit,
        itemIt->stream_item_index
    );
    const auto item_data_available = formatted_text.has_value();
    const auto item_data_requires_materialization = presentation.source_kind != session_detail::StreamItemDataSourceKind::unavailable &&
        presentation.state != session_detail::StreamItemDataState::synthetic;
    const auto item_data_status_text = item_data_available || !item_data_requires_materialization
        ? QString::fromStdString(session_detail::format_selected_stream_item_data_status_text(presentation))
        : stream_item_data_materialization_failure_text();
    packet_details_model_.setStreamItemDataPresentation(
        item_data_available,
        QString::fromStdString(session_detail::to_string(
            item_data_available || !item_data_requires_materialization
                ? presentation.semantic_kind
                : session_detail::StreamItemDataSemanticKind::other)),
        QString::fromStdString(session_detail::to_string(
            item_data_available || !item_data_requires_materialization
                ? presentation.source_kind
                : session_detail::StreamItemDataSourceKind::unavailable)),
        QString::fromStdString(session_detail::to_string(
            item_data_available || !item_data_requires_materialization
                ? presentation.state
                : session_detail::StreamItemDataState::unavailable)),
        QString::fromStdString(session_detail::to_string(presentation.assembly_kind)),
        item_data_available ? presentation.available_length : 0U,
        optional_length_variant(presentation.declared_length),
        optional_length_variant(presentation.contributing_unit_count),
        presentation.contributing_unit_kind.has_value()
            ? QString::fromStdString(session_detail::to_string(*presentation.contributing_unit_kind))
            : QString {},
        optional_length_variant(presentation.quic_crypto_stream_offset),
        item_data_status_text,
        formatted_text.has_value() ? QString::fromStdString(*formatted_text) : QString {}
    );
    packet_details_model_.setPayloadText(formatted_text.has_value() ? QString::fromStdString(*formatted_text) : QString {});
}

void MainController::reloadActiveDetails() {
    switch (details_selection_context_) {
    case DetailsSelectionContext::packet:
        reloadSelectedPacketDetails();
        break;
    case DetailsSelectionContext::stream:
        reloadSelectedStreamDetails();
        break;
    case DetailsSelectionContext::none:
        break;
    }
}

void MainController::beginOpenProgress() {
    const bool changed = !is_opening_ || open_progress_packets_ != 0U || open_progress_bytes_ != 0U ||
        open_progress_total_bytes_ != 0U || open_progress_percent_ != 0.0 || !active_open_input_path_.isEmpty() || active_open_as_index_;
    is_opening_ = true;
    open_progress_packets_ = 0;
    open_progress_bytes_ = 0;
    open_progress_total_bytes_ = 0;
    open_progress_percent_ = 0.0;
    if (changed) {
        emit openProgressChanged();
        emit actionAvailabilityChanged();
    }
}

void MainController::updateOpenProgress(const OpenProgress& progress) {
    const auto packets = static_cast<qulonglong>(progress.packets_processed);
    const auto bytes = static_cast<qulonglong>(progress.bytes_processed);
    const auto totalBytes = static_cast<qulonglong>(progress.total_bytes);
    const auto percent = std::clamp(progress.percent(), 0.0, 1.0);

    if (is_opening_ && open_progress_packets_ == packets && open_progress_bytes_ == bytes &&
        open_progress_total_bytes_ == totalBytes && open_progress_percent_ == percent) {
        return;
    }

    is_opening_ = true;
    open_progress_packets_ = packets;
    open_progress_bytes_ = bytes;
    open_progress_total_bytes_ = totalBytes;
    open_progress_percent_ = percent;
    emit openProgressChanged();
}

void MainController::finishOpenProgress() {
    const bool changed = is_opening_ || open_progress_packets_ != 0U || open_progress_bytes_ != 0U ||
        open_progress_total_bytes_ != 0U || open_progress_percent_ != 0.0 || !active_open_input_path_.isEmpty() || active_open_as_index_;
    is_opening_ = false;
    open_progress_packets_ = 0;
    open_progress_bytes_ = 0;
    open_progress_total_bytes_ = 0;
    open_progress_percent_ = 0.0;
    active_open_input_path_.clear();
    active_open_as_index_ = false;
    if (changed) {
        emit openProgressChanged();
        emit actionAvailabilityChanged();
    }
}


void MainController::setApplyingSession(const bool applying) {
    if (is_applying_session_ == applying) {
        return;
    }

    is_applying_session_ = applying;
    emit sessionApplicationStateChanged();
}

void MainController::setOpenErrorText(const QString& text) {
    if (open_error_text_ == text) {
        return;
    }

    open_error_text_ = text;
    emit openErrorTextChanged();
}

void MainController::setAnalysisSequenceExportState(const bool inProgress, const QString& statusText, const bool statusIsError) {
    const bool progressChanged = analysis_sequence_export_in_progress_ != inProgress;
    if (!progressChanged && analysis_sequence_export_status_text_ == statusText && analysis_sequence_export_status_is_error_ == statusIsError) {
        return;
    }

    analysis_sequence_export_in_progress_ = inProgress;
    analysis_sequence_export_status_text_ = statusText;
    analysis_sequence_export_status_is_error_ = statusIsError;
    emit analysisSequenceExportStateChanged();
    if (progressChanged) {
        emit actionAvailabilityChanged();
    }
}

void MainController::setSmartExportState(
    const bool inProgress,
    const qulonglong packetsProcessed,
    const qulonglong totalPackets,
    const QString& progressText
) {
    const bool progress_changed = smart_export_in_progress_ != inProgress ||
        smart_export_progress_packets_ != packetsProcessed ||
        smart_export_progress_total_packets_ != totalPackets ||
        smart_export_progress_text_ != progressText;
    if (!progress_changed) {
        return;
    }

    const bool availability_changed = smart_export_in_progress_ != inProgress;
    smart_export_in_progress_ = inProgress;
    smart_export_progress_packets_ = packetsProcessed;
    smart_export_progress_total_packets_ = totalPackets;
    smart_export_progress_text_ = progressText;
    emit smartExportStateChanged();
    if (availability_changed) {
        emit actionAvailabilityChanged();
    }
}

void MainController::setIndexSaveState(
    const bool inProgress,
    const bool cancelRequested,
    const double progressPercent,
    const QString& progressText
) {
    const bool changed = index_save_in_progress_ != inProgress ||
        index_save_cancel_requested_ != cancelRequested ||
        index_save_progress_percent_ != progressPercent ||
        index_save_progress_text_ != progressText;
    if (!changed) {
        return;
    }

    const bool availability_changed = index_save_in_progress_ != inProgress;
    index_save_in_progress_ = inProgress;
    index_save_cancel_requested_ = cancelRequested;
    index_save_progress_percent_ = progressPercent;
    index_save_progress_text_ = progressText;
    emit indexSaveStateChanged();
    if (availability_changed) {
        emit actionAvailabilityChanged();
    }
}

void MainController::setStatusText(const QString& text, const bool isError) {
    if (status_text_ == text && status_is_error_ == isError) {
        return;
    }

    status_text_ = text;
    status_is_error_ = isError;
    emit statusTextChanged();
}

QString MainController::chooseAdvancedFlowFilterOpenFile() const {
    if (advanced_flow_filter_open_file_chooser_for_tests_) {
        return advanced_flow_filter_open_file_chooser_for_tests_();
    }

    const QString directory = last_directory_path_.isEmpty() ? QString {} : last_directory_path_;
    return QFileDialog::getOpenFileName(
        nullptr,
        QStringLiteral("Open Advanced Filter"),
        directory,
        QStringLiteral("Advanced Filter Files (*.filter);;All Files (*)")
    );
}

QString MainController::chooseAdvancedFlowFilterSaveAsFile(const QString& suggestedFileName) const {
    if (advanced_flow_filter_save_as_file_chooser_for_tests_) {
        return advanced_flow_filter_save_as_file_chooser_for_tests_(suggestedFileName);
    }

    QFileDialog dialog {};
    dialog.setAcceptMode(QFileDialog::AcceptSave);
    dialog.setOption(QFileDialog::DontConfirmOverwrite, false);
    dialog.setFileMode(QFileDialog::AnyFile);
    dialog.setDirectory(last_directory_path_);
    dialog.setWindowTitle(QStringLiteral("Save Advanced Filter As"));
    dialog.setNameFilter(QStringLiteral("Advanced Filter Files (*.filter);;All Files (*)"));
    dialog.setDefaultSuffix(QStringLiteral("filter"));
    if (!suggestedFileName.isEmpty()) {
        dialog.selectFile(suggestedFileName);
    }

    if (dialog.exec() != QFileDialog::Accepted) {
        return {};
    }

    const QStringList files = dialog.selectedFiles();
    return files.isEmpty() ? QString {} : files.first();
}

QString MainController::chooseFile(const bool forIndex) const {
    const QString directory = last_directory_path_.isEmpty() ? QString {} : last_directory_path_;
    const QString title = forIndex ? QStringLiteral("Open Index") : QStringLiteral("Open Capture");
    const QString filter = forIndex
        ? QStringLiteral("Index Files (*.idx);;All Files (*)")
        : QStringLiteral("Capture Files (*.pcap *.pcapng);;All Files (*)");

    return QFileDialog::getOpenFileName(nullptr, title, directory, filter);
}

QString MainController::chooseSaveFile(const bool forIndex) const {
    QFileDialog dialog {};
    dialog.setAcceptMode(QFileDialog::AcceptSave);
    dialog.setOption(QFileDialog::DontConfirmOverwrite, false);
    dialog.setFileMode(QFileDialog::AnyFile);
    dialog.setDirectory(last_directory_path_);

    if (forIndex) {
        dialog.setWindowTitle(QStringLiteral("Save Analysis Index"));
        dialog.setNameFilter(QStringLiteral("Index Files (*.idx);;All Files (*)"));
        dialog.setDefaultSuffix(QStringLiteral("idx"));
    } else {
        dialog.setWindowTitle(QStringLiteral("Export Flow PCAP"));
        dialog.setNameFilter(QStringLiteral("PCAP Files (*.pcap);;All Files (*)"));
        dialog.setDefaultSuffix(QStringLiteral("pcap"));
    }

    if (dialog.exec() != QFileDialog::Accepted) {
        return {};
    }

    const QStringList files = dialog.selectedFiles();
    return files.isEmpty() ? QString {} : files.first();
}

QString MainController::chooseDirectory(const QString& title) const {
    return QFileDialog::getExistingDirectory(
        nullptr,
        title,
        last_directory_path_,
        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks
    );
}

MainController::AdvancedFlowFilterOpenUnsavedDecision
MainController::confirmAdvancedFlowFilterOpenUnsaved(const bool fileBackedDirty) const {
    if (advanced_flow_filter_unsaved_open_decision_for_tests_) {
        return advanced_flow_filter_unsaved_open_decision_for_tests_(fileBackedDirty);
    }

    QMessageBox box {};
    box.setIcon(QMessageBox::Warning);
    box.setWindowTitle(QStringLiteral("Unsaved Advanced Filter"));
    box.setText(QStringLiteral("Opening another filter would discard unsaved Advanced Filter changes."));
    box.setInformativeText(
        fileBackedDirty
            ? QStringLiteral("Save the current file-backed filter before opening another filter?")
            : QStringLiteral("Save the current custom filter before opening another filter?")
    );

    QAbstractButton* save_button = box.addButton(
        fileBackedDirty
            ? QStringLiteral("Save and open")
            : QStringLiteral("Save As and open"),
        QMessageBox::AcceptRole
    );
    QAbstractButton* discard_button = box.addButton(QStringLiteral("Discard and open"), QMessageBox::DestructiveRole);
    QAbstractButton* cancel_button = box.addButton(QMessageBox::Cancel);

    box.exec();
    if (box.clickedButton() == save_button) {
        return fileBackedDirty
            ? AdvancedFlowFilterOpenUnsavedDecision::save_and_open
            : AdvancedFlowFilterOpenUnsavedDecision::save_as_and_open;
    }
    if (box.clickedButton() == discard_button) {
        return AdvancedFlowFilterOpenUnsavedDecision::discard_and_open;
    }
    Q_UNUSED(cancel_button);
    return AdvancedFlowFilterOpenUnsavedDecision::cancel;
}

MainController::AdvancedFlowFilterClearDecision
MainController::confirmAdvancedFlowFilterClear(const bool fileBackedDirty) const {
    if (advanced_flow_filter_clear_decision_for_tests_) {
        return advanced_flow_filter_clear_decision_for_tests_(fileBackedDirty);
    }

    QMessageBox box {};
    box.setIcon(QMessageBox::Warning);
    box.setWindowTitle(QStringLiteral("Clear Advanced Filter"));
    box.setText(QStringLiteral("Clearing the filter would discard the current Advanced Filter configuration."));
    box.setInformativeText(
        fileBackedDirty
            ? QStringLiteral("This filter has unsaved changes. Save the changes before clearing the filter?")
            : QStringLiteral("This custom filter has not been saved. Save it before clearing the filter?")
    );

    QAbstractButton* save_button = box.addButton(
        fileBackedDirty
            ? QStringLiteral("Save and clear")
            : QStringLiteral("Save As and clear"),
        QMessageBox::AcceptRole
    );
    QAbstractButton* discard_button = box.addButton(QStringLiteral("Discard and clear"), QMessageBox::DestructiveRole);
    QAbstractButton* cancel_button = box.addButton(QMessageBox::Cancel);

    box.exec();
    if (box.clickedButton() == save_button) {
        return fileBackedDirty
            ? AdvancedFlowFilterClearDecision::save_and_clear
            : AdvancedFlowFilterClearDecision::save_as_and_clear;
    }
    if (box.clickedButton() == discard_button) {
        return AdvancedFlowFilterClearDecision::discard_and_clear;
    }
    Q_UNUSED(cancel_button);
    return AdvancedFlowFilterClearDecision::cancel;
}

QString MainController::advancedFlowFilterSuggestedFileName() const {
    if (const auto* source_path = advanced_flow_filter_document_state_.source_path(); source_path != nullptr) {
        const QString file_name = QString::fromStdWString(source_path->filename().wstring());
        if (!file_name.trimmed().isEmpty()) {
            return file_name;
        }
    }
    return QStringLiteral("advanced-filter.filter");
}

bool MainController::synchronizeAdvancedFlowFilterDraft(QString* errorText) {
    if (!advanced_flow_filter_document_state_.is_editing()) {
        advanced_flow_filter_document_state_.begin_edit();
        advanced_flow_filter_editor_model_.initializeFromCurrentDocument();
        refreshAdvancedFlowFilterProtocolPathApplicability();
    }

    return advanced_flow_filter_editor_model_.synchronizeDraftSections(errorText);
}

bool MainController::saveAdvancedFlowFilterDraftToPath(const std::filesystem::path& path, QString* errorText) {
    const auto* draft_document = advanced_flow_filter_document_state_.draft_document();
    if (draft_document == nullptr) {
        if (errorText != nullptr) {
            *errorText = QStringLiteral("Advanced filter draft is unavailable.");
        }
        return false;
    }

    const auto formatted = session_detail::format_advanced_flow_filter_text(*draft_document);
    if (formatted.status != session_detail::AdvancedFlowFilterTextFormatStatus::ok) {
        if (errorText != nullptr) {
            const QString message = formatted.issue.has_value()
                ? QString::fromStdString(formatted.issue->message)
                : QStringLiteral("Advanced filter document could not be formatted.");
            *errorText = message;
        }
        return false;
    }

    if (advanced_flow_filter_save_error_for_tests_) {
        if (const auto injected_error = advanced_flow_filter_save_error_for_tests_(path); injected_error.has_value()) {
            if (errorText != nullptr) {
                *errorText = *injected_error;
            }
            return false;
        }
    }

    const QString path_text = QString::fromStdWString(path.wstring());
    QSaveFile file(path_text);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (errorText != nullptr) {
            *errorText = format_advanced_filter_write_error(path, file.errorString());
        }
        return false;
    }

    const QByteArray bytes = QByteArray::fromStdString(formatted.text);
    if (file.write(bytes) != bytes.size()) {
        file.cancelWriting();
        if (errorText != nullptr) {
            *errorText = format_advanced_filter_write_error(path, file.errorString());
        }
        return false;
    }

    if (!file.commit()) {
        if (errorText != nullptr) {
            *errorText = format_advanced_filter_write_error(path, file.errorString());
        }
        return false;
    }

    advanced_flow_filter_document_state_.accept_saved_document(*draft_document, path);
    advanced_flow_filter_editor_model_.setValidationText({});
    refreshAdvancedFlowFilterProtocolPathApplicability();
    refreshAdvancedFlowFilter();
    setLastDirectoryFromPath(path);
    emit smartExportCurrentFilterAvailableChanged();
    emit advancedFlowFilterPresentationChanged();
    return true;
}

void MainController::finalizeAdvancedFlowFilterClearAll() {
    advanced_flow_filter_document_state_.clear_all();
    refreshAdvancedFlowFilterEditingPresentation();
}

void MainController::refreshAdvancedFlowFilterEditingPresentation() {
    if (advanced_flow_filter_document_state_.is_editing()) {
        advanced_flow_filter_editor_model_.initializeFromCurrentDocument();
        refreshAdvancedFlowFilterProtocolPathApplicability();
    } else {
        advanced_flow_filter_editor_model_.clearTransientState();
    }
    advanced_flow_filter_editor_model_.setValidationText({});
    advanced_flow_filter_protocol_path_selector_model_.clearSelection();
    advanced_flow_filter_protocol_path_selector_row_ = -1;
    refreshAdvancedFlowFilter();
    emit smartExportCurrentFilterAvailableChanged();
    emit advancedFlowFilterPresentationChanged();
}

bool MainController::openAdvancedFlowFilterFileAtPath(const std::filesystem::path& path, QString* errorText) {
    const QString path_text = QString::fromStdWString(path.wstring());
    QFile file(path_text);
    if (!file.open(QIODevice::ReadOnly)) {
        if (errorText != nullptr) {
            *errorText = QStringLiteral("Failed to open advanced filter file %1: %2")
                .arg(QFileInfo(path_text).fileName(), file.errorString());
        }
        return false;
    }

    const auto read_result = read_advanced_flow_filter_file_bounded(file);
    if (read_result.status == AdvancedFlowFilterFileReadResult::Status::read_failed) {
        if (errorText != nullptr) {
            *errorText = format_advanced_filter_read_error(path, file.errorString());
        }
        return false;
    }

    if (read_result.status == AdvancedFlowFilterFileReadResult::Status::too_large) {
        if (errorText != nullptr) {
            *errorText = format_advanced_filter_file_too_large_error(path);
        }
        return false;
    }

    const QByteArray& bytes = read_result.bytes;
    const auto parse_result = session_detail::parse_advanced_flow_filter_text(std::string_view(bytes.constData(), static_cast<std::size_t>(bytes.size())));
    if (parse_result.status != session_detail::AdvancedFlowFilterTextParseStatus::ok) {
        if (errorText != nullptr) {
            *errorText = format_advanced_filter_text_parse_error(parse_result, path);
        }
        return false;
    }

    advanced_flow_filter_document_state_.accept_opened_document(parse_result.document, path);
    advanced_flow_filter_editor_model_.initializeFromCurrentDocument();
    advanced_flow_filter_editor_model_.setValidationText({});
    advanced_flow_filter_protocol_path_selector_model_.clearSelection();
    advanced_flow_filter_protocol_path_selector_row_ = -1;
    refreshAdvancedFlowFilterProtocolPathApplicability();
    refreshAdvancedFlowFilter();
    setLastDirectoryFromPath(path);
    emit smartExportCurrentFilterAvailableChanged();
    emit advancedFlowFilterPresentationChanged();
    return true;
}

QString MainController::chooseSequenceCsvSaveFile() const {
    QFileDialog dialog {};
    dialog.setAcceptMode(QFileDialog::AcceptSave);
    dialog.setOption(QFileDialog::DontConfirmOverwrite, false);
    dialog.setFileMode(QFileDialog::AnyFile);
    dialog.setDirectory(last_directory_path_);
    dialog.setWindowTitle(QStringLiteral("Export Flow Sequence CSV"));
    dialog.setNameFilter(QStringLiteral("CSV Files (*.csv);;All Files (*)"));
    dialog.setDefaultSuffix(QStringLiteral("csv"));

    if (dialog.exec() != QFileDialog::Accepted) {
        return {};
    }

    const QStringList files = dialog.selectedFiles();
    return files.isEmpty() ? QString {} : files.first();
}

QString MainController::chooseFlowInfoCsvSaveFile() const {
    QFileDialog dialog {};
    dialog.setAcceptMode(QFileDialog::AcceptSave);
    dialog.setOption(QFileDialog::DontConfirmOverwrite, false);
    dialog.setFileMode(QFileDialog::AnyFile);
    dialog.setDirectory(last_directory_path_);
    dialog.setWindowTitle(QStringLiteral("Export All Flows Info to CSV"));
    dialog.setNameFilter(QStringLiteral("CSV Files (*.csv);;All Files (*)"));
    dialog.setDefaultSuffix(QStringLiteral("csv"));
    dialog.selectFile(QStringLiteral("flows_manifest.csv"));

    if (dialog.exec() != QFileDialog::Accepted) {
        return {};
    }

    const QStringList files = dialog.selectedFiles();
    return files.isEmpty() ? QString {} : files.first();
}

QString MainController::chooseProtocolPathTreeSaveFile() const {
    QFileDialog dialog {};
    dialog.setAcceptMode(QFileDialog::AcceptSave);
    dialog.setOption(QFileDialog::DontConfirmOverwrite, false);
    dialog.setFileMode(QFileDialog::AnyFile);
    dialog.setDirectory(last_directory_path_);
    dialog.setWindowTitle(QStringLiteral("Export Protocol Path Tree"));
    dialog.setNameFilter(QStringLiteral("Text Files (*.txt);;All Files (*)"));
    dialog.setDefaultSuffix(QStringLiteral("txt"));
    dialog.selectFile(QStringLiteral("protocol-path-tree.txt"));

    if (dialog.exec() != QFileDialog::Accepted) {
        return {};
    }

    const QStringList files = dialog.selectedFiles();
    return files.isEmpty() ? QString {} : files.first();
}

QString MainController::chooseByteExportSaveFile(
    const QString& title,
    const QString& suggestedFileName,
    const QString& suggestedExtension,
    const bool binaryOutput
) const {
    QFileDialog dialog {};
    dialog.setAcceptMode(QFileDialog::AcceptSave);
    dialog.setOption(QFileDialog::DontConfirmOverwrite, false);
    dialog.setFileMode(QFileDialog::AnyFile);
    dialog.setDirectory(last_directory_path_);
    dialog.setWindowTitle(title);
    dialog.setNameFilter(
        binaryOutput
            ? QStringLiteral("Binary Files (*.%1);;All Files (*)").arg(suggestedExtension)
            : QStringLiteral("Text Files (*.%1);;All Files (*)").arg(suggestedExtension)
    );
    dialog.setDefaultSuffix(suggestedExtension);
    if (!suggestedFileName.isEmpty()) {
        dialog.selectFile(suggestedFileName);
    }

    if (dialog.exec() != QFileDialog::Accepted) {
        return {};
    }

    const QStringList files = dialog.selectedFiles();
    return files.isEmpty() ? QString {} : files.first();
}

void MainController::setLastDirectoryFromPath(const std::filesystem::path& path) {
    std::filesystem::path directory = path;
    if (!std::filesystem::is_directory(directory)) {
        directory = directory.parent_path();
    }

    if (directory.empty()) {
        return;
    }

    const QString newPath = QString::fromStdWString(directory.wstring());
    if (last_directory_path_ == newPath) {
        return;
    }

    last_directory_path_ = newPath;
}

}  // namespace pfl































