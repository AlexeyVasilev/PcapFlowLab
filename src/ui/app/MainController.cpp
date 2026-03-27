#include "ui/app/MainController.h"

#include <array>
#include <filesystem>
#include <limits>

#include <QFileDialog>
#include <QStringList>

#include "cli/CliImportMode.h"

namespace pfl {

namespace {

constexpr qulonglong kInvalidPacketSelection = std::numeric_limits<qulonglong>::max();
constexpr int kFlowTabIndex = 0;
constexpr int kStatsTabIndex = 1;
constexpr int kSettingsTabIndex = 2;

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
        return FlowListModel::SortKey::address_a;
    case 6:
        return FlowListModel::SortKey::port_a;
    case 7:
        return FlowListModel::SortKey::address_b;
    case 8:
        return FlowListModel::SortKey::port_b;
    case 9:
        return FlowListModel::SortKey::packets;
    case 10:
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
    case FlowListModel::SortKey::address_a:
        return 5;
    case FlowListModel::SortKey::port_a:
        return 6;
    case FlowListModel::SortKey::address_b:
        return 7;
    case FlowListModel::SortKey::port_b:
        return 8;
    case FlowListModel::SortKey::packets:
        return 9;
    case FlowListModel::SortKey::bytes:
        return 10;
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

QString buildPacketSummary(const PacketDetails& details) {
    QStringList lines {};

    appendSection(lines, QStringLiteral("Packet"), {
        QStringLiteral("Packet index in file: %1").arg(details.packet_index),
        QStringLiteral("Captured Length: %1").arg(details.captured_length),
        QStringLiteral("Original Length: %1").arg(details.original_length),
    });

    if (details.captured_length != details.original_length) {
        appendSection(lines, QStringLiteral("Warnings"), {
            QStringLiteral("Packet is truncated in capture"),
            QStringLiteral("Captured Length: %1").arg(details.captured_length),
            QStringLiteral("Original Length: %1").arg(details.original_length),
        });
    }

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

bool MainController::canSaveIndex() const noexcept {
    return session_.has_capture();
}

bool MainController::canExportSelectedFlow() const noexcept {
    return session_.has_capture() && selected_flow_index_ >= 0;
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

qulonglong MainController::ipv6FlowCount() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.ipv6.flow_count);
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

QObject* MainController::packetDetailsModel() noexcept {
    return &packet_details_model_;
}

int MainController::selectedFlowIndex() const noexcept {
    return selected_flow_index_;
}

qulonglong MainController::selectedPacketIndex() const noexcept {
    return selected_packet_index_;
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

bool MainController::saveAnalysisIndex(const QString& path) {
    const QString trimmedPath = path.trimmed();
    if (trimmedPath.isEmpty()) {
        setStatusText(QStringLiteral("No output file selected."), true);
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

bool MainController::exportSelectedFlow(const QString& path) {
    if (selected_flow_index_ < 0) {
        setStatusText(QStringLiteral("No flow selected for export."), true);
        return false;
    }

    const QString trimmedPath = path.trimmed();
    if (trimmedPath.isEmpty()) {
        setStatusText(QStringLiteral("No output file selected."), true);
        return false;
    }

    const auto filesystemPath = std::filesystem::path {trimmedPath.toStdWString()};
    const bool exported = session_.export_flow_to_pcap(static_cast<std::size_t>(selected_flow_index_), filesystemPath);
    if (!exported) {
        setStatusText(QStringLiteral("Failed to export selected flow."), true);
        return false;
    }

    setLastDirectoryFromPath(filesystemPath);
    setStatusText(QStringLiteral("Flow exported successfully."));
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
    clearFlowSelection();
    setFlowFilterText(filterText.trimmed());
    setCurrentTabIndex(kFlowTabIndex);
}

void MainController::drillDownToEndpoint(const QString& endpointText) {
    drillDownToFlows(endpointText);
}

void MainController::drillDownToPort(const quint32 port) {
    drillDownToFlows(QString::number(port));
}

bool MainController::openPath(const QString& path, const bool asIndex) {
    setStatusText({});

    const QString trimmed_path = path.trimmed();
    if (trimmed_path.isEmpty()) {
        setOpenErrorText(QStringLiteral("No file selected."));
        resetLoadedState();
        emit stateChanged();
        emit flowFilterTextChanged();
        emit flowSortChanged();
        return false;
    }

    const std::filesystem::path filesystem_path = std::filesystem::path {trimmed_path.toStdWString()};
    setLastDirectoryFromPath(filesystem_path);
    auto import_options = capture_import_options_for_ui_index(capture_open_mode_);
    import_options.settings = pending_analysis_settings_;
    const bool opened = asIndex
        ? session_.load_index(filesystem_path)
        : session_.open_capture(filesystem_path, import_options);

    if (!opened) {
        setOpenErrorText(asIndex
            ? QStringLiteral("Failed to open index file.")
            : QStringLiteral("Failed to open capture file."));
        resetLoadedState();
        emit stateChanged();
        emit flowFilterTextChanged();
        emit flowSortChanged();
        return false;
    }

    setOpenErrorText({});
    applyLoadedState(trimmed_path);
    emit stateChanged();
    emit flowFilterTextChanged();
    emit flowSortChanged();
    return true;
}

void MainController::setCaptureOpenMode(const int mode) {
    const int normalized_mode = (mode == kCliDeepImportModeIndex)
        ? kCliDeepImportModeIndex
        : kCliFastImportModeIndex;

    if (capture_open_mode_ == normalized_mode) {
        return;
    }

    capture_open_mode_ = normalized_mode;
    emit captureOpenModeChanged();
}

void MainController::setHttpUsePathAsServiceHint(const bool enabled) {
    if (pending_analysis_settings_.http_use_path_as_service_hint == enabled) {
        return;
    }

    pending_analysis_settings_.http_use_path_as_service_hint = enabled;
    emit httpUsePathAsServiceHintChanged();
}

void MainController::setCurrentTabIndex(const int index) {
    const int normalizedIndex = (index == kStatsTabIndex || index == kSettingsTabIndex)
        ? index
        : kFlowTabIndex;
    if (current_tab_index_ == normalizedIndex) {
        return;
    }

    current_tab_index_ = normalizedIndex;
    emit currentTabIndexChanged();
}

void MainController::setSelectedFlowIndex(const int index) {
    if (selected_flow_index_ == index) {
        return;
    }

    selected_flow_index_ = index;

    if (selected_flow_index_ >= 0) {
        packet_model_.refresh(session_.list_flow_packets(static_cast<std::size_t>(selected_flow_index_)));
    } else {
        packet_model_.clear();
    }

    clearPacketSelection();
    emit selectedFlowIndexChanged();
    emit actionAvailabilityChanged();
}

void MainController::setSelectedPacketIndex(const qulonglong packetIndex) {
    if (selected_packet_index_ == packetIndex) {
        return;
    }

    selected_packet_index_ = packetIndex;

    if (selected_packet_index_ == kInvalidPacketSelection) {
        packet_details_model_.clear();
        emit selectedPacketIndexChanged();
        return;
    }

    const auto packet = session_.find_packet(static_cast<std::uint64_t>(selected_packet_index_));
    if (!packet.has_value()) {
        packet_details_model_.clear();
        emit selectedPacketIndexChanged();
        return;
    }

    const auto details = session_.read_packet_details(*packet);
    const std::string hex = session_.read_packet_hex_dump(*packet);
    const std::string payload_hex = session_.read_packet_payload_hex_dump(*packet);
    const std::string protocol_text = session_.read_packet_protocol_details_text(*packet);

    if (!details.has_value()) {
        packet_details_model_.clear();
        emit selectedPacketIndexChanged();
        return;
    }

    packet_details_model_.setPacketDetailsText(buildPacketSummary(*details));
    packet_details_model_.setHexText(QString::fromStdString(hex));
    packet_details_model_.setPayloadText(buildPayloadText(*details, payload_hex));
    packet_details_model_.setProtocolText(QString::fromStdString(protocol_text));
    emit selectedPacketIndexChanged();
}

void MainController::setFlowFilterText(const QString& text) {
    if (flow_model_.filterText() == text) {
        return;
    }

    flow_model_.setFilterText(text);
    synchronizeFlowSelection();
    emit flowFilterTextChanged();
}

void MainController::clearPacketSelection() {
    const bool selectionChanged = selected_packet_index_ != kInvalidPacketSelection;
    selected_packet_index_ = kInvalidPacketSelection;
    packet_details_model_.clear();

    if (selectionChanged) {
        emit selectedPacketIndexChanged();
    }
}

void MainController::clearFlowSelection() {
    const bool flowChanged = selected_flow_index_ != -1;
    selected_flow_index_ = -1;
    packet_model_.clear();
    clearPacketSelection();

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
    setCurrentTabIndex(kFlowTabIndex);
    protocol_summary_ = {};
    session_ = {};
    flow_model_.resetViewState();
    flow_model_.clear();
    top_endpoints_model_.clear();
    top_ports_model_.clear();
    clearFlowSelection();
    emit actionAvailabilityChanged();
}

void MainController::applyLoadedState(const QString& path) {
    current_input_path_ = path;
    setCurrentTabIndex(kFlowTabIndex);
    protocol_summary_ = session_.protocol_summary();
    flow_model_.resetViewState();
    flow_model_.refresh(session_.list_flows());
    refreshTopSummaryModels();
    clearFlowSelection();
    emit actionAvailabilityChanged();
}

void MainController::refreshTopSummaryModels() {
    const auto summary = session_.top_summary();
    top_endpoints_model_.refreshEndpoints(summary.endpoints_by_bytes);
    top_ports_model_.refreshPorts(summary.ports_by_bytes);
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
        dialog.setWindowTitle(QStringLiteral("Export Selected Flow"));
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

