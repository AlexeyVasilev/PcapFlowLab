#include "ui/app/MainController.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <filesystem>
#include <limits>
#include <memory>

#include <QFileDialog>
#include <QStringList>
#include <QThread>
#include <QTimer>
#include <QVariantMap>

#include "../../../core/open_context.h"
#include "cli/CliImportMode.h"

namespace pfl {

namespace {

constexpr qulonglong kInvalidPacketSelection = std::numeric_limits<qulonglong>::max();
constexpr qulonglong kInvalidStreamSelection = std::numeric_limits<qulonglong>::max();
constexpr int kFlowTabIndex = 0;
constexpr int kAnalysisTabIndex = 1;
constexpr int kStatsTabIndex = 2;
constexpr int kSettingsTabIndex = 3;
constexpr int kStatisticsModeFlows = 0;
constexpr int kStatisticsModePackets = 1;
constexpr int kStatisticsModeBytes = 2;
constexpr std::size_t kInitialPacketRows = 30U;
constexpr std::size_t kPacketRowBatchSize = 30U;
constexpr std::size_t kInitialStreamItems = 15U;
constexpr std::size_t kStreamItemBatchSize = 15U;
constexpr std::size_t kInitialStreamPacketBudget = 30U;
constexpr std::size_t kStreamPacketBatchSize = 30U;

struct OpenJobResult {
    bool opened {false};
    bool cancelled {false};
    bool as_index {false};
    QString input_path {};
    QString error_text {};
    CaptureSession session {};
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
    case ProtocolId::tcp:
        return "TCP";
    case ProtocolId::udp:
        return "UDP";
    case ProtocolId::icmpv6:
        return "ICMPv6";
    default:
        return QStringLiteral("%1").arg(protocol);
    }
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

QString formatIpv4Address(const std::uint32_t address) {
    return QStringLiteral("%1.%2.%3.%4")
        .arg((address >> 24U) & 0xFFU)
        .arg((address >> 16U) & 0xFFU)
        .arg((address >> 8U) & 0xFFU)
        .arg(address & 0xFFU);
}

QString formatIpv4Address(const std::array<std::uint8_t, 4>& address) {
    return QStringLiteral("%1.%2.%3.%4")
        .arg(address[0])
        .arg(address[1])
        .arg(address[2])
        .arg(address[3]);
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

QString buildPayloadText(const PacketDetails& details, const std::string& payloadHexDump) {
    if (!payloadHexDump.empty()) {
        return QString::fromStdString(payloadHexDump);
    }

    if (details.has_tcp || details.has_udp) {
        return QStringLiteral("No transport payload");
    }

    return QStringLiteral("Transport payload not available for this packet");
}

QString formatPacketIndices(const std::vector<std::uint64_t>& packetIndices) {
    QStringList values {};
    values.reserve(static_cast<qsizetype>(packetIndices.size()));

    for (const auto packetIndex : packetIndices) {
        values.push_back(QString::number(packetIndex));
    }

    return values.join(QStringLiteral(", "));
}

QString formatFlowPacketNumbers(
    const std::vector<std::uint64_t>& packetIndices,
    const std::map<std::uint64_t, std::uint64_t>& flowPacketNumbers
) {
    QStringList values {};

    for (const auto packetIndex : packetIndices) {
        const auto flowIt = flowPacketNumbers.find(packetIndex);
        if (flowIt == flowPacketNumbers.end()) {
            continue;
        }

        values.push_back(QStringLiteral("#%1").arg(flowIt->second));
    }

    return values.join(QStringLiteral(", "));
}

QString formatContributingPackets(
    const StreamItemRow& item,
    const std::map<std::uint64_t, std::uint64_t>& flowPacketNumbers
) {
    const QString fileIndices = formatPacketIndices(item.packet_indices);
    const QString flowNumbers = formatFlowPacketNumbers(item.packet_indices, flowPacketNumbers);

    if (!flowNumbers.isEmpty()) {
        return QStringLiteral("flow %1 (file %2)").arg(flowNumbers, fileIndices);
    }

    return QStringLiteral("(file %1)").arg(fileIndices);
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

QString format_rate_value(const double value, const QString& suffix) {
    return QStringLiteral("%1 %2").arg(value, 0, 'f', 3).arg(suffix);
}

QString format_size_value(const double value) {
    return QStringLiteral("%1 B").arg(value, 0, 'f', 1);
}

QString format_size_value(const std::uint32_t value) {
    return QStringLiteral("%1 B").arg(value);
}

QString format_size_value(const std::uint64_t value) {
    return QStringLiteral("%1 B").arg(value);
}

QString buildStreamItemSummary(
    const StreamItemRow& item,
    const std::map<std::uint64_t, std::uint64_t>& flowPacketNumbers
) {
    QStringList lines {};

    appendSection(lines, QStringLiteral("Stream Item"), {
        QStringLiteral("Direction: %1").arg(QString::fromStdString(item.direction_text)),
        QStringLiteral("Label: %1").arg(QString::fromStdString(item.label)),
        QStringLiteral("Byte Count: %1").arg(item.byte_count),
        QStringLiteral("Packet Count: %1").arg(item.packet_count),
        QStringLiteral("Contributing Packets: %1").arg(formatContributingPackets(item, flowPacketNumbers)),
    });

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

QString buildPacketSummary(const PacketDetails& details, const PacketRef& packet) {
    QStringList lines {};

    appendSection(lines, QStringLiteral("Packet"), {
        QStringLiteral("Packet index in file: %1").arg(details.packet_index),
        QStringLiteral("Captured Length: %1").arg(details.captured_length),
        QStringLiteral("Original Length: %1").arg(details.original_length),
    });

    QStringList warnings {};
    if (packet.is_ip_fragmented) {
        warnings.push_back(QStringLiteral("Packet is IP-fragmented"));
    }
    if (details.captured_length != details.original_length) {
        warnings.push_back(QStringLiteral("Packet is truncated in capture"));
        warnings.push_back(QStringLiteral("Captured Length: %1").arg(details.captured_length));
        warnings.push_back(QStringLiteral("Original Length: %1").arg(details.original_length));
    }
    appendSection(lines, QStringLiteral("Warnings"), warnings);

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
        appendSection(lines, QStringLiteral("ARP"), {
            QStringLiteral("Opcode: %1").arg(details.arp.opcode),
            QStringLiteral("Sender IPv4: %1").arg(formatIpv4Address(details.arp.sender_ipv4)),
            QStringLiteral("Target IPv4: %1").arg(formatIpv4Address(details.arp.target_ipv4)),
        });
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
        appendSection(lines, QStringLiteral("TCP"), {
            QStringLiteral("Source Port: %1").arg(details.tcp.src_port),
            QStringLiteral("Destination Port: %1").arg(details.tcp.dst_port),
            QStringLiteral("Flags: %1").arg(formatTcpFlags(details.tcp.flags)),
        });
    }

    if (details.has_udp) {
        appendSection(lines, QStringLiteral("UDP"), {
            QStringLiteral("Source Port: %1").arg(details.udp.src_port),
            QStringLiteral("Destination Port: %1").arg(details.udp.dst_port),
        });
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

}  // namespace

MainController::MainController(QObject* parent)
    : QObject(parent)
    , capture_open_mode_(kCliFastImportModeIndex)
    , current_tab_index_(kFlowTabIndex)
    , selected_packet_index_(kInvalidPacketSelection) {
    QObject::connect(&flow_model_, &FlowListModel::checkedFlowsChanged, this, [this]() {
        emit selectedFlowCountChanged();
        emit actionAvailabilityChanged();
    });
}

MainController::~MainController() {
    cleanupOpenThread();
}

QString MainController::currentInputPath() const {
    return current_input_path_;
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
    return session_.has_source_capture();
}

bool MainController::openedFromIndex() const noexcept {
    return session_.opened_from_index();
}

bool MainController::canAttachSourceCapture() const noexcept {
    return !is_opening_ && session_.opened_from_index() && !session_.has_source_capture();
}

bool MainController::canSaveIndex() const noexcept {
    return !is_opening_ && session_.has_capture() && session_.has_source_capture() && !session_.is_partial_open();
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
    return !is_opening_ && session_.has_source_capture() && selected_flow_index_ >= 0;
}

qulonglong MainController::selectedFlowCount() const noexcept {
    return static_cast<qulonglong>(flow_model_.checkedFlowCount());
}

bool MainController::canExportSelectedFlows() const noexcept {
    return !is_opening_ && session_.has_source_capture() && flow_model_.checkedFlowCount() > 0;
}

bool MainController::canExportUnselectedFlows() const noexcept {
    return !is_opening_ && session_.has_source_capture() && flow_model_.totalFlowCount() > flow_model_.checkedFlowCount();
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
    return selected_flow_index_ >= 0 && loaded_packet_row_count_ < total_packet_row_count_;
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

qulonglong MainController::analysisTotalPackets() const noexcept {
    return current_flow_analysis_.has_value() ? static_cast<qulonglong>(current_flow_analysis_->total_packets) : 0U;
}

qulonglong MainController::analysisTotalBytes() const noexcept {
    return current_flow_analysis_.has_value() ? static_cast<qulonglong>(current_flow_analysis_->total_bytes) : 0U;
}

QString MainController::analysisPacketsPerSecondText() const {
    return current_flow_analysis_.has_value()
        ? format_rate_value(current_flow_analysis_->packets_per_second, QStringLiteral("pkt/s"))
        : QString {};
}

QString MainController::analysisBytesPerSecondText() const {
    return current_flow_analysis_.has_value()
        ? format_rate_value(current_flow_analysis_->bytes_per_second, QStringLiteral("B/s"))
        : QString {};
}

QString MainController::analysisAveragePacketSizeText() const {
    return current_flow_analysis_.has_value()
        ? format_size_value(current_flow_analysis_->average_packet_size_bytes)
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

QString MainController::analysisMaxPacketSizeText() const {
    return current_flow_analysis_.has_value()
        ? format_size_value(current_flow_analysis_->max_packet_size_bytes)
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

QString MainController::analysisDominantDirectionText() const {
    return current_flow_analysis_.has_value() && !current_flow_analysis_->dominant_direction_text.empty()
        ? QString::fromStdString(current_flow_analysis_->dominant_direction_text)
        : QString {};
}

QString MainController::analysisProtocolHint() const {
    return current_flow_analysis_.has_value() && !current_flow_analysis_->protocol_hint.empty()
        ? QString::fromStdString(current_flow_analysis_->protocol_hint).toUpper()
        : QString {};
}

QString MainController::analysisServiceHint() const {
    return current_flow_analysis_.has_value() && !current_flow_analysis_->service_hint.empty()
        ? QString::fromStdString(current_flow_analysis_->service_hint)
        : QString {};
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

qulonglong MainController::analysisTcpFinPackets() const noexcept {
    return current_flow_analysis_.has_value() ? static_cast<qulonglong>(current_flow_analysis_->tcp_fin_packets) : 0U;
}

qulonglong MainController::analysisTcpRstPackets() const noexcept {
    return current_flow_analysis_.has_value() ? static_cast<qulonglong>(current_flow_analysis_->tcp_rst_packets) : 0U;
}

qulonglong MainController::analysisBurstCount() const noexcept {
    return current_flow_analysis_.has_value() ? static_cast<qulonglong>(current_flow_analysis_->burst_count) : 0U;
}

qulonglong MainController::analysisLongestBurstPacketCount() const noexcept {
    return current_flow_analysis_.has_value()
        ? static_cast<qulonglong>(current_flow_analysis_->longest_burst_packet_count)
        : 0U;
}

QString MainController::analysisLargestBurstBytesText() const {
    return current_flow_analysis_.has_value()
        ? format_size_value(current_flow_analysis_->largest_burst_bytes)
        : QString {};
}

qulonglong MainController::analysisIdleGapCount() const noexcept {
    return current_flow_analysis_.has_value() ? static_cast<qulonglong>(current_flow_analysis_->idle_gap_count) : 0U;
}

QString MainController::analysisLargestIdleGapText() const {
    return current_flow_analysis_.has_value()
        ? format_duration_us(current_flow_analysis_->largest_idle_gap_us)
        : QString {};
}

qulonglong MainController::analysisPacketsAToB() const noexcept {
    return current_flow_analysis_.has_value() ? static_cast<qulonglong>(current_flow_analysis_->packets_a_to_b) : 0U;
}

qulonglong MainController::analysisPacketsBToA() const noexcept {
    return current_flow_analysis_.has_value() ? static_cast<qulonglong>(current_flow_analysis_->packets_b_to_a) : 0U;
}

qulonglong MainController::analysisBytesAToB() const noexcept {
    return current_flow_analysis_.has_value() ? static_cast<qulonglong>(current_flow_analysis_->bytes_a_to_b) : 0U;
}

qulonglong MainController::analysisBytesBToA() const noexcept {
    return current_flow_analysis_.has_value() ? static_cast<qulonglong>(current_flow_analysis_->bytes_b_to_a) : 0U;
}

QVariantList MainController::analysisInterArrivalHistogram() const {
    QVariantList rows {};
    if (!current_flow_analysis_.has_value()) {
        return rows;
    }

    rows.reserve(static_cast<qsizetype>(current_flow_analysis_->inter_arrival_histogram_rows.size()));
    for (const auto& histogram_row : current_flow_analysis_->inter_arrival_histogram_rows) {
        QVariantMap row {};
        row.insert(QStringLiteral("bucketLabel"), QString::fromStdString(histogram_row.bucket_label));
        row.insert(QStringLiteral("packetCount"), static_cast<qulonglong>(histogram_row.packet_count));
        rows.push_back(row);
    }

    return rows;
}

QVariantList MainController::analysisPacketSizeHistogram() const {
    QVariantList rows {};
    if (!current_flow_analysis_.has_value()) {
        return rows;
    }

    rows.reserve(static_cast<qsizetype>(current_flow_analysis_->packet_size_histogram_rows.size()));
    for (const auto& histogram_row : current_flow_analysis_->packet_size_histogram_rows) {
        QVariantMap row {};
        row.insert(QStringLiteral("bucketLabel"), QString::fromStdString(histogram_row.bucket_label));
        row.insert(QStringLiteral("packetCount"), static_cast<qulonglong>(histogram_row.packet_count));
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
        QVariantMap row {};
        row.insert(QStringLiteral("packetNumber"), static_cast<qulonglong>(preview_row.flow_packet_number));
        row.insert(QStringLiteral("direction"), QString::fromStdString(preview_row.direction_text));
        row.insert(QStringLiteral("deltaTimeText"), format_duration_us(preview_row.delta_time_us));
        row.insert(QStringLiteral("capturedLength"), preview_row.captured_length);
        row.insert(QStringLiteral("payloadLength"), preview_row.payload_length);
        row.insert(QStringLiteral("timestampText"), QString::fromStdString(preview_row.timestamp_text));
        rows.push_back(row);
    }

    return rows;
}

qulonglong MainController::packetCount() const noexcept {
    return static_cast<qulonglong>(session_.summary().packet_count);
}
qulonglong MainController::flowCount() const noexcept {
    return static_cast<qulonglong>(session_.summary().flow_count);
}

qulonglong MainController::totalBytes() const noexcept {
    return static_cast<qulonglong>(session_.summary().total_bytes);
}

QVariantList MainController::protocolHintDistribution() const {
    auto makeRow = [](const char* label, const ProtocolStats& stats) {
        QVariantMap row {};
        row.insert(QStringLiteral("title"), QString::fromUtf8(label));
        row.insert(QStringLiteral("flows"), static_cast<qulonglong>(stats.flow_count));
        row.insert(QStringLiteral("packets"), static_cast<qulonglong>(stats.packet_count));
        row.insert(QStringLiteral("bytes"), static_cast<qulonglong>(stats.total_bytes));
        return row;
    };

    QVariantList rows {};
    rows.reserve(11);
    rows.push_back(makeRow("HTTP", protocol_summary_.hint_http));
    rows.push_back(makeRow("TLS", protocol_summary_.hint_tls));
    rows.push_back(makeRow("DNS", protocol_summary_.hint_dns));
    rows.push_back(makeRow("QUIC", protocol_summary_.hint_quic));
    rows.push_back(makeRow("SSH", protocol_summary_.hint_ssh));
    rows.push_back(makeRow("STUN", protocol_summary_.hint_stun));
    rows.push_back(makeRow("BitTorrent", protocol_summary_.hint_bittorrent));
    rows.push_back(makeRow("Mail protocols", protocol_summary_.hint_mail_protocols));
    rows.push_back(makeRow("DHCP", protocol_summary_.hint_dhcp));
    rows.push_back(makeRow("mDNS", protocol_summary_.hint_mdns));
    rows.push_back(makeRow("Unknown", protocol_summary_.hint_unknown));
    return rows;
}

qulonglong MainController::tcpFlowCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.tcp.flow_count);
}

qulonglong MainController::tcpPacketCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.tcp.packet_count);
}

qulonglong MainController::tcpTotalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.tcp.total_bytes);
}

qulonglong MainController::udpFlowCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.udp.flow_count);
}

qulonglong MainController::udpPacketCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.udp.packet_count);
}

qulonglong MainController::udpTotalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.udp.total_bytes);
}

qulonglong MainController::otherFlowCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.other.flow_count);
}

qulonglong MainController::otherPacketCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.other.packet_count);
}

qulonglong MainController::otherTotalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.other.total_bytes);
}

qulonglong MainController::ipv4FlowCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.ipv4.flow_count);
}

qulonglong MainController::ipv4PacketCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.ipv4.packet_count);
}

qulonglong MainController::ipv4TotalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.ipv4.total_bytes);
}

qulonglong MainController::ipv6FlowCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.ipv6.flow_count);
}

qulonglong MainController::ipv6PacketCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.ipv6.packet_count);
}

qulonglong MainController::ipv6TotalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.ipv6.total_bytes);
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

int MainController::statisticsMode() const noexcept {
    return statistics_mode_;
}

int MainController::captureOpenMode() const noexcept {
    return capture_open_mode_;
}

bool MainController::httpUsePathAsServiceHint() const noexcept {
    return pending_analysis_settings_.http_use_path_as_service_hint;
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

qulonglong MainController::selectedPacketIndex() const noexcept {
    return selected_packet_index_;
}

qulonglong MainController::selectedStreamItemIndex() const noexcept {
    return selected_stream_item_index_;
}

QString MainController::flowFilterText() const {
    return flow_model_.filterText();
}

int MainController::flowSortColumn() const noexcept {
    return column_from_sort_key(flow_model_.sortKey());
}

bool MainController::flowSortAscending() const noexcept {
    return flow_model_.sortAscending();
}

bool MainController::openCaptureFile(const QString& path) {
    return openPath(path, false);
}

bool MainController::openIndexFile(const QString& path) {
    return openPath(path, true);
}

bool MainController::attachSourceCapture(const QString& path) {
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

bool MainController::saveAnalysisIndex(const QString& path) {
    const QString trimmedPath = path.trimmed();
    if (trimmedPath.isEmpty()) {
        setStatusText(QStringLiteral("No output file selected."), true);
        return false;
    }

    if (session_.is_partial_open()) {
        setStatusText(QStringLiteral("Saving an index from a partial capture is not supported yet."), true);
        return false;
    }

    const auto filesystemPath = std::filesystem::path {trimmedPath.toStdWString()};
    const bool saved = session_.save_index(filesystemPath);
    if (!saved) {
        setStatusText(QStringLiteral("Failed to save analysis index."), true);
        return false;
    }

    setLastDirectoryFromPath(filesystemPath);
    setStatusText(QStringLiteral("Analysis index saved successfully."));
    return true;
}

bool MainController::exportFlows(
    const QString& path,
    const std::vector<int>& flowIndices,
    const QString& emptySelectionMessage,
    const QString& failureMessage,
    const QString& successMessage
) {
    if (flowIndices.empty()) {
        setStatusText(emptySelectionMessage, true);
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
    setFlowFilterText(filterText.trimmed());
}

void MainController::drillDownToEndpoint(const QString& endpointText) {
    drillDownToFlows(endpointText);
}

void MainController::drillDownToPort(const quint32 port) {
    drillDownToFlows(QString::number(port));
}

void MainController::setFlowDetailsTabIndex(const int index) {
    const bool streamActive = index == 1;
    if (stream_tab_active_ == streamActive) {
        return;
    }

    stream_tab_active_ = streamActive;
    if (stream_tab_active_ && selected_flow_index_ >= 0 && !stream_state_materialized_for_selected_flow_) {
        refreshSelectedStreamItems(true);
    }
}

void MainController::setCaptureOpenMode(const int mode) {
    const int normalizedMode = (mode == kCliDeepImportModeIndex)
        ? kCliDeepImportModeIndex
        : kCliFastImportModeIndex;

    if (capture_open_mode_ == normalizedMode) {
        return;
    }

    capture_open_mode_ = normalizedMode;
    emit captureOpenModeChanged();
}

void MainController::setStatisticsMode(const int mode) {
    const int normalizedMode = (mode == kStatisticsModePackets)
        ? kStatisticsModePackets
        : (mode == kStatisticsModeBytes ? kStatisticsModeBytes : kStatisticsModeFlows);

    if (statistics_mode_ == normalizedMode) {
        return;
    }

    statistics_mode_ = normalizedMode;
    emit statisticsModeChanged();
}

void MainController::setHttpUsePathAsServiceHint(const bool enabled) {
    if (pending_analysis_settings_.http_use_path_as_service_hint == enabled) {
        return;
    }

    pending_analysis_settings_.http_use_path_as_service_hint = enabled;
    emit httpUsePathAsServiceHintChanged();
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
        if (analysis_tab_active_ && selected_flow_index_ >= 0) {
            refreshSelectedFlowAnalysis();
        } else if (!analysis_tab_active_ && analysis_loading_) {
            ++active_analysis_request_id_;
            analysis_loading_ = false;
            emit analysisStateChanged();
        }
    }
    emit currentTabIndexChanged();
}

void MainController::setSelectedFlowIndex(const int index) {
    if (selected_flow_index_ == index) {
        return;
    }

    selected_flow_index_ = index;
    clearPacketSelection();
    clearStreamSelection();
    clearSelectedFlowAnalysis();
    clearSelectedFlowAnalysis();
    current_flow_packet_numbers_.clear();
    current_stream_items_.clear();
    stream_model_.clear();
    stream_loading_ = false;
    loaded_stream_item_count_ = 0U;
    total_stream_item_count_ = 0U;
    stream_packet_window_count_ = 0U;
    stream_item_budget_count_ = 0U;
    can_load_more_stream_items_ = false;
    stream_state_materialized_for_selected_flow_ = false;

    if (selected_flow_index_ >= 0) {
        refreshSelectedFlowPackets(true);
        maybeEnrichSelectedFlowServiceHint();
        if (stream_tab_active_) {
            refreshSelectedStreamItems(true);
        } else {
            emit streamListStateChanged();
        }
        if (analysis_tab_active_) {
            refreshSelectedFlowAnalysis();
        }
    } else {
        packet_model_.clear();
        loaded_packet_row_count_ = 0U;
        total_packet_row_count_ = 0U;
        packets_loading_ = false;
        emit packetListStateChanged();
        emit streamListStateChanged();
    }

    emit selectedFlowIndexChanged();
    emit actionAvailabilityChanged();
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
    if (flow_model_.filterText() == text) {
        return;
    }

    flow_model_.setFilterText(text);
    synchronizeFlowSelection();
    emit flowFilterTextChanged();
}

void MainController::maybeEnrichSelectedFlowServiceHint() {
    if (selected_flow_index_ < 0 || !session_.has_source_capture()) {
        return;
    }

    const auto row = flow_model_.rowForFlowIndex(selected_flow_index_);
    if (row < 0) {
        return;
    }

    const auto modelIndex = flow_model_.index(row, 0);
    const auto protocolHint = flow_model_.data(modelIndex, FlowListModel::ProtocolHintRole).toString();
    const auto serviceHint = flow_model_.data(modelIndex, FlowListModel::ServiceHintRole).toString();
    if (protocolHint.compare(QStringLiteral("QUIC"), Qt::CaseInsensitive) != 0 || !serviceHint.isEmpty()) {
        return;
    }

    const auto derivedServiceHint = session_.derive_quic_service_hint_for_flow(static_cast<std::size_t>(selected_flow_index_));
    if (!derivedServiceHint.has_value() || derivedServiceHint->empty()) {
        return;
    }

    flow_model_.setServiceHintForFlowIndex(selected_flow_index_, QString::fromStdString(*derivedServiceHint));
}

void MainController::refreshSelectedFlowPackets(const bool resetRows) {
    const bool previousLoading = packets_loading_;
    const auto previousLoaded = loaded_packet_row_count_;
    const auto previousTotal = total_packet_row_count_;

    if (selected_flow_index_ < 0) {
        packet_model_.clear();
        current_flow_packet_numbers_.clear();
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
    const auto rows = session_.list_flow_packets(static_cast<std::size_t>(selected_flow_index_), offset, batchSize);

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

void MainController::refreshSelectedStreamItems(const bool resetRows) {
    const bool previousLoading = stream_loading_;
    const auto previousLoaded = loaded_stream_item_count_;
    const auto previousTotal = total_stream_item_count_;
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
        if (previousLoading != stream_loading_ || previousLoaded != loaded_stream_item_count_ || previousTotal != total_stream_item_count_ || previousCanLoadMore != can_load_more_stream_items_) {
            emit streamListStateChanged();
        }
        return;
    }

    const auto flowIndex = static_cast<std::size_t>(selected_flow_index_);
    const auto totalFlowPacketCount = session_.flow_packet_count(flowIndex);
    if (resetRows) {
        stream_packet_window_count_ = std::min(totalFlowPacketCount, kInitialStreamPacketBudget);
        stream_item_budget_count_ = kInitialStreamItems;
    } else {
        stream_packet_window_count_ = std::min(totalFlowPacketCount, stream_packet_window_count_ + kStreamPacketBatchSize);
        stream_item_budget_count_ += kStreamItemBatchSize;
    }

    stream_loading_ = true;
    const auto requestLimit = stream_item_budget_count_ + 1U;
    const bool packetBudgetExhausted = stream_packet_window_count_ < totalFlowPacketCount;

    auto rows = packetBudgetExhausted
        ? session_.list_flow_stream_items_for_packet_prefix(flowIndex, stream_packet_window_count_, requestLimit)
        : session_.list_flow_stream_items(flowIndex, 0U, requestLimit);

    const bool hasMoreItems = rows.size() > stream_item_budget_count_;
    if (hasMoreItems) {
        rows.resize(stream_item_budget_count_);
    }

    current_stream_items_ = rows;
    stream_model_.refresh(current_stream_items_);

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

    if (previousLoading != stream_loading_ || previousLoaded != loaded_stream_item_count_ || previousTotal != total_stream_item_count_ || previousCanLoadMore != can_load_more_stream_items_) {
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

void MainController::clearPacketSelection() {
    const bool selectionChanged = selected_packet_index_ != kInvalidPacketSelection;
    const bool wasActive = details_selection_context_ == DetailsSelectionContext::packet;
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
    const bool packetStateChanged = packets_loading_ || loaded_packet_row_count_ != 0U || total_packet_row_count_ != 0U;
    const bool streamStateChanged = stream_loading_ || loaded_stream_item_count_ != 0U || total_stream_item_count_ != 0U || stream_packet_window_count_ != 0U || stream_item_budget_count_ != 0U || can_load_more_stream_items_ || stream_state_materialized_for_selected_flow_;
    selected_flow_index_ = -1;
    packet_model_.clear();
    current_stream_items_.clear();
    current_flow_packet_numbers_.clear();
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

    if (packetStateChanged) {
        emit packetListStateChanged();
    }
    if (streamStateChanged) {
        emit streamListStateChanged();
    }

    if (flowChanged) {
        emit selectedFlowIndexChanged();
        emit actionAvailabilityChanged();
    }
}

void MainController::synchronizeFlowSelection() {
    if (selected_flow_index_ >= 0 && !flow_model_.containsFlowIndex(selected_flow_index_)) {
        clearFlowSelection();
    }
}

void MainController::resetLoadedState() {
    current_input_path_.clear();
    finishOpenProgress();
    session_ = {};
    protocol_summary_ = {};
    quic_recognition_stats_ = {};
    tls_recognition_stats_ = {};
    flow_model_.clear();
    flow_model_.resetViewState();
    packet_model_.clear();
    current_stream_items_.clear();
    current_flow_packet_numbers_.clear();
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
    selected_packet_index_ = kInvalidPacketSelection;
    selected_stream_item_index_ = kInvalidStreamSelection;
    details_selection_context_ = DetailsSelectionContext::none;
    ++active_analysis_request_id_;
    analysis_loading_ = false;
    emit analysisStateChanged();
    current_flow_analysis_.reset();
}

void MainController::applyLoadedState(const QString& path) {
    current_input_path_ = path;
    protocol_summary_ = session_.protocol_summary();
    quic_recognition_stats_ = session_.quic_recognition_stats();
    tls_recognition_stats_ = session_.tls_recognition_stats();
    flow_model_.clear();
    flow_model_.resetViewState();
    flow_model_.refresh(session_.list_flows());
    refreshTopSummaryModels();
    clearFlowSelection();
    setOpenErrorText({});
    setStatusText({});
    emit stateChanged();
    emit sourceAvailabilityChanged();
    emit actionAvailabilityChanged();
}

void MainController::refreshTopSummaryModels() {
    const auto top = session_.top_summary();
    top_endpoints_model_.refreshEndpoints(top.endpoints_by_bytes);
    top_ports_model_.refreshPorts(top.ports_by_bytes);
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

    setOpenErrorText({});
    setStatusText({});
    beginOpenProgress();

    const auto filesystemPath = std::filesystem::path {trimmedPath.toStdWString()};
    setLastDirectoryFromPath(filesystemPath);

    ++active_open_job_id_;
    const qulonglong jobId = active_open_job_id_;
    auto importOptions = capture_import_options_for_ui_index(capture_open_mode_);
    importOptions.settings = pending_analysis_settings_;
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
    finishOpenProgress();

    if (cancellationWon) {
        setOpenErrorText({});
        setStatusText(QStringLiteral("Open cancelled."));
        return;
    }

    if (!opened) {
        const QString genericError = asIndex
            ? QStringLiteral("Failed to open analysis index.")
            : QStringLiteral("Failed to open capture file.");
        setOpenErrorText(genericError);
        setStatusText(errorText.isEmpty() ? genericError : errorText, true);
        return;
    }

    session_ = std::move(session);
    applyLoadedState(path);
    if (session_.is_partial_open()) {
        setStatusText(format_partial_open_warning_message(session_.partial_open_failure()));
    }
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

    const auto packet = session_.find_packet(static_cast<std::uint64_t>(selected_packet_index_));
    if (!packet.has_value()) {
        packet_details_model_.clear();
        return;
    }

    const auto details = session_.read_packet_details(*packet);
    if (!details.has_value()) {
        packet_details_model_.clear();
        return;
    }

    const auto hexDump = session_.read_packet_hex_dump(*packet);
    const auto payloadHexDump = session_.read_packet_payload_hex_dump(*packet);
    const auto protocolText = session_.read_packet_protocol_details_text(*packet);

    packet_details_model_.setPacketDetailsText(buildPacketSummary(*details, *packet));
    packet_details_model_.setHexText(QString::fromStdString(hexDump));
    packet_details_model_.setPayloadText(buildPayloadText(*details, payloadHexDump));
    packet_details_model_.setProtocolText(QString::fromStdString(protocolText));
}

void MainController::reloadSelectedStreamDetails() {
    if (selected_stream_item_index_ == kInvalidStreamSelection) {
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
    packet_details_model_.setPacketDetailsText(buildStreamItemSummary(*itemIt, current_flow_packet_numbers_));

    if (!itemIt->payload_hex_text.empty() || !itemIt->protocol_text.empty()) {
        packet_details_model_.setHexText(QStringLiteral("Raw packet hex is not available for this stream item."));
        packet_details_model_.setPayloadText(
            itemIt->payload_hex_text.empty()
                ? QStringLiteral("Transport payload is not available for this stream item.")
                : QString::fromStdString(itemIt->payload_hex_text)
        );
        packet_details_model_.setProtocolText(
            itemIt->protocol_text.empty()
                ? QStringLiteral("No protocol-specific details available for this stream item.")
                : QString::fromStdString(itemIt->protocol_text)
        );
        return;
    }

    if (itemIt->packet_indices.size() == 1U) {
        const auto packet = session_.find_packet(itemIt->packet_indices.front());
        if (packet.has_value()) {
            const auto details = session_.read_packet_details(*packet);
            const auto hexDump = session_.read_packet_hex_dump(*packet);
            const auto payloadHexDump = session_.read_packet_payload_hex_dump(*packet);
            const auto protocolText = session_.read_packet_protocol_details_text(*packet);

            packet_details_model_.setHexText(QString::fromStdString(hexDump));
            if (details.has_value()) {
                packet_details_model_.setPayloadText(buildPayloadText(*details, payloadHexDump));
            } else if (!payloadHexDump.empty()) {
                packet_details_model_.setPayloadText(QString::fromStdString(payloadHexDump));
            } else {
                packet_details_model_.setPayloadText(QStringLiteral("Transport payload not available for this stream item."));
            }
            packet_details_model_.setProtocolText(QString::fromStdString(protocolText));
            return;
        }
    }

    packet_details_model_.setHexText(QStringLiteral("Raw packet hex is not available for this stream item."));
    packet_details_model_.setPayloadText(QStringLiteral("Transport payload is not available for this stream item."));
    packet_details_model_.setProtocolText(QStringLiteral("No protocol-specific details available for this stream item."));
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
        open_progress_total_bytes_ != 0U || open_progress_percent_ != 0.0;
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
        open_progress_total_bytes_ != 0U || open_progress_percent_ != 0.0;
    is_opening_ = false;
    open_progress_packets_ = 0;
    open_progress_bytes_ = 0;
    open_progress_total_bytes_ = 0;
    open_progress_percent_ = 0.0;
    if (changed) {
        emit openProgressChanged();
        emit actionAvailabilityChanged();
    }
}

void MainController::setOpenErrorText(const QString& text) {
    if (open_error_text_ == text) {
        return;
    }

    open_error_text_ = text;
    emit openErrorTextChanged();
}

void MainController::setStatusText(const QString& text, const bool isError) {
    if (status_text_ == text && status_is_error_ == isError) {
        return;
    }

    status_text_ = text;
    status_is_error_ = isError;
    emit statusTextChanged();
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


















