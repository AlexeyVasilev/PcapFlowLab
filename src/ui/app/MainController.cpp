#include "ui/app/MainController.h"

#include "app/session/SelectedFlowDiagnostics.h"
#include "app/session/SelectedFlowPacketSemantics.h"
#include "app/session/SessionFormatting.h"
#include "core/decode/PacketDecodeSupport.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <sstream>
#include <span>

#include <QClipboard>
#include <QCoreApplication>
#include <QFileDialog>
#include <QGuiApplication>
#include <QRegularExpression>
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
constexpr int kSmartExportFlowScopeCurrentFlow = 0;
constexpr int kSmartExportFlowScopeSelectedFlows = 1;
constexpr int kSmartExportFlowScopeUnselectedFlows = 2;
constexpr int kSmartExportFlowScopeAllFlows = 3;
constexpr int kSmartExportOutputModeSingleFile = 0;
constexpr int kSmartExportOutputModeSeparateFilePerFlow = 1;
constexpr int kSmartExportBaseModeAllPackets = 0;
constexpr int kSmartExportBaseModeFirstNPackets = 1;
constexpr int kSmartExportBaseModeFirstMOriginalBytes = 2;
constexpr int kStatisticsModeFlows = 0;
constexpr int kStatisticsModePackets = 1;
constexpr int kStatisticsModeBytes = 2;
constexpr std::size_t kInitialPacketRows = 30U;
constexpr std::size_t kPacketRowBatchSize = 30U;
constexpr std::size_t kInitialStreamItems = 15U;
constexpr std::size_t kStreamItemBatchSize = 15U;
constexpr std::size_t kInitialStreamPacketBudget = 30U;
constexpr std::size_t kStreamPacketBatchSize = 30U;
constexpr int kSessionApplyOverlayDelayMs = 40;
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
        : (protocol.compare(QStringLiteral("UDP"), Qt::CaseInsensitive) == 0 ? QStringLiteral("udp.port") : QString {});

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

std::string format_elapsed_ms(const double elapsed_ms) {
    std::ostringstream out {};
    out << std::fixed << std::setprecision(2) << elapsed_ms << " ms";
    return out.str();
}

std::string selected_flow_diagnostics_identity(const FlowListModel& flow_model, const int selected_flow_index) {
    if (selected_flow_index < 0) {
        return "flow_index=none";
    }

    const auto row = flow_model.rowForFlowIndex(selected_flow_index);
    if (row < 0) {
        return "flow_index=" + std::to_string(selected_flow_index) + " row=hidden";
    }

    const auto model_index = flow_model.index(row, 0);
    const auto family = flow_model.data(model_index, FlowListModel::FamilyRole).toString();
    const auto protocol = flow_model.data(model_index, FlowListModel::ProtocolRole).toString();
    const auto hint = flow_model.data(model_index, FlowListModel::ProtocolHintRole).toString();
    const auto service = flow_model.data(model_index, FlowListModel::ServiceHintRole).toString();
    const auto address_a = flow_model.data(model_index, FlowListModel::AddressARole).toString();
    const auto port_a = flow_model.data(model_index, FlowListModel::PortARole).toUInt();
    const auto address_b = flow_model.data(model_index, FlowListModel::AddressBRole).toString();
    const auto port_b = flow_model.data(model_index, FlowListModel::PortBRole).toUInt();
    const auto packets = flow_model.data(model_index, FlowListModel::PacketsRole).toULongLong();
    const auto bytes = flow_model.data(model_index, FlowListModel::BytesRole).toULongLong();

    std::ostringstream out {};
    out << "flow_index=" << selected_flow_index
        << " packets=" << packets
        << " bytes=" << bytes
        << " family=" << family.toStdString()
        << " proto=" << protocol.toStdString()
        << " hint=" << (hint.isEmpty() ? "-" : hint.toStdString())
        << " service=" << (service.isEmpty() ? "-" : service.toStdString())
        << " endpoints=" << address_a.toStdString() << ':' << port_a
        << " -> " << address_b.toStdString() << ':' << port_b;
    return out.str();
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

std::optional<std::uint64_t> parse_positive_u64(const QString& text) {
    bool ok = false;
    const auto value = text.trimmed().toULongLong(&ok);
    if (!ok || value == 0U) {
        return std::nullopt;
    }

    return static_cast<std::uint64_t>(value);
}

std::optional<std::uint32_t> derive_transport_payload_length_from_headers(
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet
) {
    return session_detail::derive_transport_payload_length_from_headers(packet_bytes, packet);
}

std::optional<std::uint32_t> derive_transport_payload_length_from_headers(
    const CaptureSession& session,
    const PacketRef& packet
) {
    return session_detail::derive_transport_payload_length_from_headers(session, packet);
}

TransportPayloadLengths resolve_transport_payload_lengths(
    const PacketDetails& details,
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet
) {
    if (!details.has_tcp && !details.has_udp) {
        return {};
    }

    return TransportPayloadLengths {
        .real_payload_length = packet.payload_length,
        .original_payload_length = derive_transport_payload_length_from_headers(packet_bytes, packet),
    };
}

void apply_original_transport_payload_lengths(CaptureSession& session, std::vector<PacketRow>& rows) {
    session_detail::apply_original_transport_payload_lengths(session, rows);
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
            .transport_payload_length = derive_transport_payload_length_from_headers(session, packet),
            .tcp_flags_text = packet_row.tcp_flags_text,
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
    if (packet.is_ip_fragmented) {
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
    if (packet.is_ip_fragmented) {
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

QString buildPayloadText(const PacketDetails& details, const std::string& payloadHexDump) {
    if (!payloadHexDump.empty()) {
        return QString::fromStdString(payloadHexDump);
    }

    if (details.has_tcp || details.has_udp) {
        return QStringLiteral("No transport payload");
    }

    return QStringLiteral("Transport payload not available for this packet");
}

QString packet_payload_tab_title(const PacketDetails& details) {
    return QString::fromStdString(session_detail::packet_payload_tab_title(details));
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

bool stream_item_uses_packet_fallback(const StreamItemRow& item) {
    return item.payload_hex_text.empty() && item.protocol_text.empty() && item.packet_indices.size() == 1U;
}

QString stream_item_details_source(const StreamItemRow& item) {
    return stream_item_uses_packet_fallback(item)
        ? QStringLiteral("Packet fallback")
        : QStringLiteral("Stream item");
}

QString stream_item_header_primary_text(const StreamItemRow& item) {
    return QString::fromStdString(item.label);
}

QString stream_item_frames_hint_text(const StreamItemRow& item) {
    const auto protocolText = QString::fromStdString(item.protocol_text);
    if (protocolText.isEmpty()) {
        return {};
    }

    QStringList hints {};

    const auto extractLineValue = [&](const QString& marker) -> QString {
        const auto markerIndex = protocolText.indexOf(marker);
        if (markerIndex < 0) {
            return {};
        }

        const auto lineStart = markerIndex + marker.size();
        auto lineEnd = protocolText.indexOf(QLatin1Char('\n'), lineStart);
        if (lineEnd < 0) {
            lineEnd = protocolText.size();
        }
        return protocolText.mid(lineStart, lineEnd - lineStart).trimmed();
    };

    const auto appendNormalizedValues = [&](const QString& text) {
        for (const auto& rawPart : text.split(QStringLiteral(","), Qt::SkipEmptyParts)) {
            auto part = rawPart.trimmed();
            if (part.compare(QStringLiteral("Protected Payload"), Qt::CaseInsensitive) == 0) {
                part = QStringLiteral("Protected payload");
            }
            if (part.compare(QStringLiteral("Packet Type: Initial"), Qt::CaseInsensitive) == 0 ||
                part.compare(QStringLiteral("Initial"), Qt::CaseInsensitive) == 0) {
                continue;
            }
            if (!part.isEmpty() && !hints.contains(part)) {
                hints.push_back(part);
            }
        }
    };

    appendNormalizedValues(extractLineValue(QStringLiteral("Frame Presence:")));
    appendNormalizedValues(extractLineValue(QStringLiteral("Packet Type:")));
    appendNormalizedValues(extractLineValue(QStringLiteral("Additional Packet Types:")));

    if (hints.isEmpty()) {
        return {};
    }

    return QStringLiteral("Frames: %1").arg(hints.join(QStringLiteral(", ")));
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
    const auto label = QString::fromStdString(item.label);
    if (label.contains(QStringLiteral("partial"), Qt::CaseInsensitive)) {
        return QStringLiteral("Partial");
    }
    if (stream_item_uses_packet_fallback(item)) {
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

bool is_quic_stream_item_label(const QString& label) {
    return label.startsWith(QStringLiteral("QUIC ")) ||
           label == QStringLiteral("QUIC Initial: ACK") ||
           label == QStringLiteral("QUIC Initial: CRYPTO") ||
           label == QStringLiteral("ACK") ||
           label == QStringLiteral("CRYPTO") ||
           label == QStringLiteral("0-RTT") ||
           label == QStringLiteral("Handshake") ||
           label == QStringLiteral("Protected payload");
}

QString stream_item_payload_tab_title(const StreamItemRow& item) {
    const auto label = QString::fromStdString(item.label);
    const auto protocolText = QString::fromStdString(item.protocol_text);

    if (protocolText.startsWith(QStringLiteral("Protocol: ARP"))) {
        return QStringLiteral("ARP Payload");
    }

    if (is_quic_stream_item_label(label) || protocolText.startsWith(QStringLiteral("QUIC"))) {
        return QStringLiteral("UDP Payload");
    }

    if (label.startsWith(QStringLiteral("TLS ")) ||
        label.startsWith(QStringLiteral("HTTP ")) ||
        label == QStringLiteral("HTTP Request") ||
        label == QStringLiteral("HTTP Response") ||
        protocolText.startsWith(QStringLiteral("TLS")) ||
        protocolText.startsWith(QStringLiteral("HTTP"))) {
        return QStringLiteral("Item Payload");
    }

    return QStringLiteral("Payload");
}

QString stream_payload_unavailable_text() {
    return QStringLiteral("Payload is not available for this stream item.");
}

QString stream_protocol_unavailable_text() {
    return QStringLiteral("Protocol details are not available for this stream item.");
}

QString source_capture_unavailable_status_text() {
    return QStringLiteral("Original source capture is unavailable. Metadata views remain available, but raw bytes, stream reconstruction, and flow export are disabled.");
}

QString source_capture_unavailable_packet_summary_text() {
    return QStringLiteral(
        "Original source capture unavailable.\n\n"
        "Byte-backed packet details are unavailable for this session.\n\n"
        "Reattach the original capture file to inspect raw bytes, payload, and protocol details.");
}

QString source_capture_unavailable_packet_raw_text() {
    return QStringLiteral("Raw packet bytes are unavailable because the original source capture cannot be read.");
}

QString source_capture_unavailable_packet_payload_text() {
    return QStringLiteral("Packet payload is unavailable because the original source capture cannot be read.");
}

QString source_capture_unavailable_packet_protocol_text() {
    return QStringLiteral("Byte-backed protocol details are unavailable because the original source capture cannot be read.");
}

QString source_capture_unavailable_stream_summary_text() {
    return QStringLiteral(
        "Original source capture unavailable.\n\n"
        "Stream reconstruction requires source packet bytes.\n\n"
        "Reattach the original capture file to inspect stream items and stream-backed details.");
}

QString source_capture_unavailable_stream_payload_text() {
    return QStringLiteral("Stream payload is unavailable because the original source capture cannot be read.");
}

QString source_capture_unavailable_stream_protocol_text() {
    return QStringLiteral("Stream protocol details are unavailable because the original source capture cannot be read.");
}

struct ProtocolField {
    QString label {};
    QString value {};
};

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

std::vector<ProtocolField> parse_protocol_fields(const QStringList& lines, const qsizetype start_index = 0) {
    std::vector<ProtocolField> fields {};
    for (auto index = std::max<qsizetype>(0, start_index); index < lines.size(); ++index) {
        const auto trimmed = lines.at(index).trimmed();
        if (trimmed.isEmpty()) {
            continue;
        }

        const auto separatorIndex = trimmed.indexOf(QStringLiteral(":"));
        if (separatorIndex < 0) {
            fields.push_back(ProtocolField {
                .label = trimmed,
                .value = {},
            });
            continue;
        }

        fields.push_back(ProtocolField {
            .label = trimmed.left(separatorIndex).trimmed(),
            .value = trimmed.mid(separatorIndex + 1).trimmed(),
        });
    }

    return fields;
}

std::vector<ProtocolField> take_protocol_fields(
    std::vector<ProtocolField>& fields,
    const QStringList& ordered_labels
) {
    std::vector<ProtocolField> taken {};
    for (const auto& label : ordered_labels) {
        const auto it = std::find_if(fields.begin(), fields.end(), [&](const ProtocolField& field) {
            return field.label == label;
        });
        if (it == fields.end()) {
            continue;
        }

        taken.push_back(*it);
        fields.erase(it);
    }

    return taken;
}

QStringList wrap_protocol_value(const QString& value, const int max_line_length = 76) {
    if (!value.contains(QStringLiteral(", "))) {
        return {value};
    }

    const auto parts = value.split(QStringLiteral(", "), Qt::SkipEmptyParts);
    QStringList lines {};
    QString currentLine {};
    for (const auto& part : parts) {
        if (currentLine.isEmpty()) {
            currentLine = part;
            continue;
        }

        if (currentLine.size() + 2 + part.size() <= max_line_length) {
            currentLine += QStringLiteral(", ") + part;
            continue;
        }

        lines.push_back(currentLine);
        currentLine = part;
    }

    if (!currentLine.isEmpty()) {
        lines.push_back(currentLine);
    }

    return lines;
}

void append_protocol_field_lines(
    QStringList& lines,
    const ProtocolField& field,
    const QStringList& multiline_labels = {}
) {
    if (field.label.isEmpty()) {
        return;
    }

    const bool multiline = multiline_labels.contains(field.label) ||
        (field.value.size() > 72 && field.value.contains(QStringLiteral(", ")));

    if (field.value.isEmpty()) {
        lines.push_back(QStringLiteral("  %1").arg(field.label));
        return;
    }

    if (!multiline) {
        lines.push_back(QStringLiteral("  %1: %2").arg(field.label, field.value));
        return;
    }

    lines.push_back(QStringLiteral("  %1:").arg(field.label));
    for (const auto& valueLine : wrap_protocol_value(field.value)) {
        lines.push_back(QStringLiteral("    %1").arg(valueLine));
    }
}

void append_protocol_section(
    QStringList& lines,
    const QString& title,
    const std::vector<ProtocolField>& fields,
    const QStringList& multiline_labels = {}
) {
    if (fields.empty()) {
        return;
    }

    if (!lines.isEmpty()) {
        lines.push_back({});
    }

    lines.push_back(title);
    for (const auto& field : fields) {
        append_protocol_field_lines(lines, field, multiline_labels);
    }
}

QString format_tls_protocol_text_from_fields(
    std::vector<ProtocolField> fields,
    const QString& title
) {
    const auto handshakeTypeIt = std::find_if(fields.begin(), fields.end(), [](const ProtocolField& field) {
        return field.label == QStringLiteral("TLS Handshake Type");
    });
    const auto handshakeType = handshakeTypeIt != fields.end() ? handshakeTypeIt->value : QString {};

    QStringList coreOrder {
        QStringLiteral("TLS Handshake Type"),
    };
    QStringList negotiationOrder {};

    if (handshakeType == QStringLiteral("ClientHello")) {
        coreOrder << QStringLiteral("SNI")
                  << QStringLiteral("ALPN")
                  << QStringLiteral("Supported Versions");
        negotiationOrder << QStringLiteral("Cipher Suites")
                         << QStringLiteral("Extensions");
    } else if (handshakeType == QStringLiteral("ServerHello")) {
        coreOrder << QStringLiteral("Selected TLS Version")
                  << QStringLiteral("Selected Cipher Suite");
        negotiationOrder << QStringLiteral("Extensions");
    } else {
        coreOrder << QStringLiteral("Selected TLS Version")
                  << QStringLiteral("Selected Cipher Suite")
                  << QStringLiteral("SNI")
                  << QStringLiteral("ALPN")
                  << QStringLiteral("Supported Versions");
        negotiationOrder << QStringLiteral("Cipher Suites")
                         << QStringLiteral("Extensions");
    }

    auto coreFields = take_protocol_fields(fields, coreOrder);
    auto negotiationFields = take_protocol_fields(fields, negotiationOrder);

    QStringList lines {};
    append_protocol_section(lines, title, coreFields);
    append_protocol_section(
        lines,
        QStringLiteral("Negotiation"),
        negotiationFields,
        {QStringLiteral("Cipher Suites"), QStringLiteral("Extensions"), QStringLiteral("Supported Versions"), QStringLiteral("ALPN")}
    );
    append_protocol_section(lines, QStringLiteral("Structure"), fields);
    if (!lines.isEmpty() && lines.front() != title) {
        lines.push_front(title);
    }
    return lines.join(QLatin1Char('\n'));
}

QString format_http_protocol_text(const QString& protocol_text) {
    const auto lines = protocol_text.split(QLatin1Char('\n'));
    if (lines.isEmpty() || lines.front().trimmed() != QStringLiteral("HTTP")) {
        return protocol_text;
    }

    auto fields = parse_protocol_fields(lines, 1);
    if (fields.empty()) {
        return protocol_text;
    }

    auto mainFields = take_protocol_fields(fields, {
        QStringLiteral("Message Type"),
        QStringLiteral("Method"),
        QStringLiteral("Path"),
        QStringLiteral("Status Code"),
        QStringLiteral("Reason"),
        QStringLiteral("Version")
    });
    auto headerFields = take_protocol_fields(fields, {
        QStringLiteral("Host"),
        QStringLiteral("Content-Type"),
        QStringLiteral("Content-Length")
    });

    QStringList formatted {};
    append_protocol_section(formatted, QStringLiteral("HTTP"), mainFields);
    append_protocol_section(formatted, QStringLiteral("Headers"), headerFields);
    append_protocol_section(formatted, QStringLiteral("Details"), fields);
    if (!formatted.isEmpty() && formatted.front() != QStringLiteral("HTTP")) {
        formatted.push_front(QStringLiteral("HTTP"));
    }
    return formatted.join(QLatin1Char('\n'));
}

QString format_tls_protocol_text(const QString& protocol_text) {
    const auto lines = protocol_text.split(QLatin1Char('\n'));
    if (lines.isEmpty() || lines.front().trimmed() != QStringLiteral("TLS")) {
        return protocol_text;
    }

    auto fields = parse_protocol_fields(lines, 1);
    if (fields.empty()) {
        return protocol_text;
    }

    return format_tls_protocol_text_from_fields(std::move(fields), QStringLiteral("TLS"));
}

QString format_quic_protocol_text(const QString& protocol_text) {
    if (!protocol_text.startsWith(QStringLiteral("QUIC"))) {
        return protocol_text;
    }

    qsizetype tlsBlockIndex = protocol_text.indexOf(QStringLiteral("\n  SNI: "));
    const auto handshakeIndex = protocol_text.indexOf(QStringLiteral("\n  TLS Handshake Type: "));
    if (tlsBlockIndex < 0 || (handshakeIndex >= 0 && handshakeIndex < tlsBlockIndex)) {
        tlsBlockIndex = handshakeIndex;
    }

    const auto quicBlock = tlsBlockIndex < 0 ? protocol_text : protocol_text.left(tlsBlockIndex);
    const auto quicLines = quicBlock.split(QLatin1Char('\n'));
    auto quicFields = parse_protocol_fields(quicLines, 1);

    QStringList formatted {};
    append_protocol_section(formatted, QStringLiteral("QUIC"), take_protocol_fields(quicFields, {
        QStringLiteral("Packet Type"),
        QStringLiteral("Additional Packet Types"),
        QStringLiteral("Header Form"),
        QStringLiteral("Version"),
        QStringLiteral("Supported Versions"),
        QStringLiteral("Frame Presence")
    }), {QStringLiteral("Supported Versions")});
    append_protocol_section(formatted, QStringLiteral("Connection IDs"), take_protocol_fields(quicFields, {
        QStringLiteral("Destination Connection ID Length"),
        QStringLiteral("Destination Connection ID"),
        QStringLiteral("Source Connection ID Length"),
        QStringLiteral("Source Connection ID")
    }));
    append_protocol_section(formatted, QStringLiteral("Details"), quicFields);

    if (tlsBlockIndex >= 0) {
        auto tlsFields = parse_protocol_fields(protocol_text.mid(tlsBlockIndex + 1).split(QLatin1Char('\n')));
        if (!tlsFields.empty()) {
            const auto tlsText = format_tls_protocol_text_from_fields(std::move(tlsFields), QStringLiteral("TLS over CRYPTO"));
            if (!tlsText.isEmpty()) {
                if (!formatted.isEmpty()) {
                    formatted.push_back({});
                }
                formatted << tlsText.split(QLatin1Char('\n'));
            }
        }
    }

    if (!formatted.isEmpty() && formatted.front() != QStringLiteral("QUIC")) {
        formatted.push_front(QStringLiteral("QUIC"));
    }
    return formatted.isEmpty() ? protocol_text : formatted.join(QLatin1Char('\n'));
}

QString normalize_stream_protocol_text(const QString& protocol_text) {
    if (protocol_text.isEmpty()) {
        return stream_protocol_unavailable_text();
    }

    QString text = protocol_text;
    text.replace(QRegularExpression(QStringLiteral("Frame Presence:\\s*")), QStringLiteral("Frame Presence: "));
    text = format_quic_protocol_text(text);
    text = format_tls_protocol_text(text);
    text = format_http_protocol_text(text);
    return text;
}

bool is_quic_protocol_text(const QString& protocol_text) {
    return protocol_text.contains(QStringLiteral("QUIC"));
}

QString selected_flow_quic_protocol_text_for_packet(
    CaptureSession& session,
    const int selected_flow_index,
    const std::uint64_t packet_index,
    const QString& protocol_text
) {
    if (selected_flow_index < 0 || !is_quic_protocol_text(protocol_text)) {
        return protocol_text;
    }

    const auto context_text = session.derive_quic_protocol_text_for_packet(
        static_cast<std::size_t>(selected_flow_index),
        packet_index
    );
    if (!context_text.has_value() || context_text->empty()) {
        return protocol_text;
    }

    return QString::fromStdString(*context_text);
}

QString selected_flow_quic_protocol_text_for_stream_item(
    CaptureSession& session,
    const int selected_flow_index,
    const StreamItemRow& item,
    const QString& protocol_text
) {
    if (selected_flow_index < 0 || !is_quic_protocol_text(protocol_text)) {
        return protocol_text;
    }

    const auto context_text = session.derive_quic_protocol_text_for_packet_context(
        static_cast<std::size_t>(selected_flow_index),
        item.packet_indices
    );
    if (!context_text.has_value() || context_text->empty()) {
        return protocol_text;
    }

    return QString::fromStdString(*context_text);
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

    if (const auto framesHint = stream_item_frames_hint_text(item); !framesHint.isEmpty()) {
        lines.insert(2, framesHint);
    }
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
    if (packet.is_ip_fragmented) {
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
    const PacketChecksumSections& checksum_sections = {}
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
    if (packet.is_ip_fragmented) {
        warnings.push_back(QStringLiteral("Packet is IP-fragmented"));
    }
    if (packet.captured_length != packet.original_length) {
        warnings.push_back(QStringLiteral("Packet is truncated in capture"));
        warnings.push_back(QStringLiteral("Captured Length: %1").arg(packet.captured_length));
        warnings.push_back(QStringLiteral("Original Length: %1").arg(packet.original_length));
    }
    warnings.append(checksum_sections.warnings);
    appendSection(lines, QStringLiteral("Warnings"), warnings);
    appendSection(lines, QStringLiteral("Checksums"), checksum_sections.summary_lines);

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
    cleanupSmartExportThread();
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
    return !is_opening_ && !smart_export_in_progress_ && session_.has_capture() && !hasSourceCapture();
}

bool MainController::canSaveIndex() const noexcept {
    return !is_opening_ && !smart_export_in_progress_ && session_.has_capture() && hasSourceCapture() && !session_.is_partial_open();
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
    return !is_opening_ && !smart_export_in_progress_ && hasSourceCapture() && selected_flow_index_ >= 0;
}

qulonglong MainController::selectedFlowCount() const noexcept {
    return static_cast<qulonglong>(flow_model_.checkedFlowCount());
}

bool MainController::canExportSelectedFlows() const noexcept {
    return !is_opening_ && !smart_export_in_progress_ && hasSourceCapture() && flow_model_.checkedFlowCount() > 0;
}

bool MainController::canExportUnselectedFlows() const noexcept {
    return !is_opening_ && !smart_export_in_progress_ && hasSourceCapture() && flow_model_.totalFlowCount() > flow_model_.checkedFlowCount();
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
    return selected_flow_index_ >= 0 && !analysis_sequence_export_in_progress_;
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
    if (!current_flow_analysis_.has_value() || selected_flow_index_ < 0) {
        return 0U;
    }

    const auto packets = session_.flow_packets(static_cast<std::size_t>(selected_flow_index_));
    if (!packets.has_value()) {
        return 0U;
    }

    std::uint64_t captured_bytes = 0U;
    for (const auto& packet : *packets) {
        captured_bytes += packet.captured_length;
    }

    return static_cast<qulonglong>(captured_bytes);
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

    std::vector<PacketRef> ordered_packets {};
    if (selected_flow_index_ >= 0) {
        if (const auto packets = session_.flow_packets(static_cast<std::size_t>(selected_flow_index_)); packets.has_value()) {
            ordered_packets = *packets;
            std::stable_sort(ordered_packets.begin(), ordered_packets.end(), [](const PacketRef& left, const PacketRef& right) {
                return packet_timestamp_us(left) < packet_timestamp_us(right);
            });
        }
    }

    rows.reserve(static_cast<qsizetype>(current_flow_analysis_->sequence_preview_rows.size()));
    for (std::size_t index = 0; index < current_flow_analysis_->sequence_preview_rows.size(); ++index) {
        const auto& preview_row = current_flow_analysis_->sequence_preview_rows[index];
        QString transport_payload_text {QStringLiteral("-")};
        if (index < ordered_packets.size()) {
            if (const auto transport_payload_length = derive_transport_payload_length_from_headers(session_, ordered_packets[index]);
                transport_payload_length.has_value()) {
                transport_payload_text = QString::number(*transport_payload_length);
            }
        }

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
    return static_cast<qulonglong>(session_.summary().packet_count);
}
qulonglong MainController::flowCount() const noexcept {
    return static_cast<qulonglong>(session_.summary().flow_count);
}

qulonglong MainController::capturedBytes() const noexcept {
    return static_cast<qulonglong>(
        protocol_summary_.tcp.captured_bytes +
        protocol_summary_.udp.captured_bytes +
        protocol_summary_.other.captured_bytes
    );
}

qulonglong MainController::originalBytes() const noexcept {
    return static_cast<qulonglong>(session_.summary().total_bytes);
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
        row.insert(QStringLiteral("capturedBytes"), static_cast<qulonglong>(stats.captured_bytes));
        row.insert(QStringLiteral("originalBytes"), static_cast<qulonglong>(stats.original_bytes));
        row.insert(QStringLiteral("bytes"), static_cast<qulonglong>(stats.original_bytes));
        return row;
    };

    QVariantList rows {};
    rows.reserve(13);
    rows.push_back(makeRow("HTTP", protocol_summary_.hint_http));
    rows.push_back(makeRow("TLS", protocol_summary_.hint_tls));
    rows.push_back(makeRow("Possible TLS", protocol_summary_.hint_possible_tls));
    rows.push_back(makeRow("DNS", protocol_summary_.hint_dns));
    rows.push_back(makeRow("QUIC", protocol_summary_.hint_quic));
    rows.push_back(makeRow("Possible QUIC", protocol_summary_.hint_possible_quic));
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

qulonglong MainController::tcpCapturedBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.tcp.captured_bytes);
}

qulonglong MainController::tcpOriginalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.tcp.original_bytes);
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

qulonglong MainController::udpOriginalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.udp.original_bytes);
}

qulonglong MainController::udpTotalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.udp.original_bytes);
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

qulonglong MainController::otherOriginalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.other.original_bytes);
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

qulonglong MainController::ipv4OriginalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.ipv4.original_bytes);
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

qulonglong MainController::ipv6OriginalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.ipv6.original_bytes);
}

qulonglong MainController::ipv6TotalBytes() const noexcept {
    return static_cast<qulonglong>(protocol_summary_.ipv6.original_bytes);
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

bool MainController::usePossibleTlsQuic() const noexcept {
    return pending_analysis_settings_.use_possible_tls_quic;
}

bool MainController::validateSelectedPacketChecksums() const noexcept {
    return validate_selected_packet_checksums_;
}


bool MainController::showWiresharkFilterForSelectedFlow() const noexcept {
    return show_wireshark_filter_for_selected_flow_;
}

QString MainController::selectedFlowWiresharkFilter() const {
    if (!show_wireshark_filter_for_selected_flow_) {
        return {};
    }

    return selected_flow_wireshark_filter(flow_model_, selected_flow_index_);
}

bool MainController::selectedFlowHasWiresharkFilter() const {
    return !selectedFlowWiresharkFilter().isEmpty();
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
    if (smart_export_in_progress_) {
        setStatusText(QStringLiteral("Wait for the current smart export to finish before opening another capture."), true);
        return false;
    }
    return openPath(path, false);
}

bool MainController::openIndexFile(const QString& path) {
    if (smart_export_in_progress_) {
        setStatusText(QStringLiteral("Wait for the current smart export to finish before opening another session."), true);
        return false;
    }
    return openPath(path, true);
}

bool MainController::attachSourceCapture(const QString& path) {
    if (smart_export_in_progress_) {
        setStatusText(QStringLiteral("Wait for the current smart export to finish before changing the source capture."), true);
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

bool MainController::saveAnalysisIndex(const QString& path) {
    if (smart_export_in_progress_) {
        setStatusText(QStringLiteral("Wait for the current smart export to finish before saving an analysis index."), true);
        return false;
    }

    const QString trimmedPath = path.trimmed();
    if (trimmedPath.isEmpty()) {
        setStatusText(QStringLiteral("No output file selected."), true);
        return false;
    }

    if (session_.is_partial_open()) {
        setStatusText(QStringLiteral("Saving an index from a partial capture is not supported yet."), true);
        return false;
    }

    if (!ensureSourceCaptureAvailable(QStringLiteral("Original source capture is unavailable. Reattach the capture file to save an analysis index."))) {
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
    default:
        setStatusText(QStringLiteral("Invalid smart export flow selection."), true);
        return false;
    }

    if (flow_indices.empty()) {
        setStatusText(empty_selection_message, true);
        return false;
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

    switch (baseSelectionMode) {
    case kSmartExportBaseModeAllPackets:
        request.base_mode = SmartFlowExportBaseMode::all_packets;
        break;
    case kSmartExportBaseModeFirstNPackets: {
        const auto value = parse_positive_u64(packetCountText);
        if (!value.has_value()) {
            setStatusText(QStringLiteral("Enter a positive packet count for smart export."), true);
            return false;
        }
        request.base_mode = SmartFlowExportBaseMode::first_n_packets;
        request.first_n_packets = *value;
        break;
    }
    case kSmartExportBaseModeFirstMOriginalBytes: {
        const auto value = parse_positive_u64(originalBytesText);
        if (!value.has_value()) {
            setStatusText(QStringLiteral("Enter a positive original-byte limit for smart export."), true);
            return false;
        }
        request.base_mode = SmartFlowExportBaseMode::first_m_original_bytes;
        request.first_m_original_bytes = *value;
        break;
    }
    default:
        setStatusText(QStringLiteral("Invalid smart export base selection."), true);
        return false;
    }

    if (request.base_mode != SmartFlowExportBaseMode::all_packets) {
        request.include_last_packet = includeLastPacket;
        request.include_every_kth_packet_after_base = includeEveryKthPacket;
        if (includeEveryKthPacket) {
            const auto value = parse_positive_u64(everyKText);
            if (!value.has_value()) {
                setStatusText(QStringLiteral("Enter a positive K value for sparse smart export retention."), true);
                return false;
            }
            request.every_kth_packet = *value;
        }
    }

    const auto filesystemPath = std::filesystem::path {trimmedPath.toStdWString()};
    setLastDirectoryFromPath(filesystemPath);
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
                completeSmartExport(job_id, trimmedPath, exported, cancelled, error);
            }, Qt::QueuedConnection);
        });

        QObject::connect(smart_export_thread_, &QThread::finished, smart_export_thread_, &QObject::deleteLater);
        smart_export_thread_->start();
        return true;
    }

    const bool exported = session_.export_smart_flows_to_pcap(request, filesystemPath);
    if (!exported) {
        setStatusText(QStringLiteral("Failed to smart-export flows."), true);
        return false;
    }

    setStatusText(QStringLiteral("Smart export completed successfully."));
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
    const auto started_at = std::chrono::steady_clock::now();
    const auto read_counters_before = selected_flow_diagnostics::snapshot_read_counters();
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

    if (selected_flow_diagnostics::enabled()) {
        std::ostringstream out {};
        out << "setFlowDetailsTabIndex index=" << index
            << " stream_active=" << (stream_tab_active_ ? "true" : "false")
            << " stream_materialized=" << (stream_state_materialized_for_selected_flow_ ? "true" : "false")
            << ' ' << selected_flow_diagnostics_identity(flow_model_, selected_flow_index_)
            << " elapsed=" << format_elapsed_ms(selected_flow_diagnostics::elapsed_ms(started_at))
            << ' ' << selected_flow_diagnostics::format_read_counter_delta(
                read_counters_before,
                selected_flow_diagnostics::snapshot_read_counters()
            );
        selected_flow_diagnostics::log(out.str());
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

void MainController::setUsePossibleTlsQuic(const bool enabled) {
    if (pending_analysis_settings_.use_possible_tls_quic == enabled) {
        return;
    }

    pending_analysis_settings_.use_possible_tls_quic = enabled;
    session_.set_analysis_settings(pending_analysis_settings_);
    if (session_.has_capture()) {
        protocol_summary_ = session_.protocol_summary();
        flow_model_.refresh(session_.list_flows());
        if (analysis_tab_active_ && selected_flow_index_ >= 0) {
            refreshSelectedFlowAnalysis();
        }
        emit stateChanged();
    }
    emit usePossibleTlsQuicChanged();
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
    emit currentTabIndexChanged();
}

void MainController::setSelectedFlowIndex(const int index) {
    if (selected_flow_index_ == index && !unrecognized_packets_selected_) {
        return;
    }

    const auto started_at = std::chrono::steady_clock::now();
    const auto read_counters_before = selected_flow_diagnostics::snapshot_read_counters();

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

    if (selected_flow_diagnostics::enabled()) {
        std::ostringstream out {};
        out << "setSelectedFlowIndex target=" << index
            << " stream_tab_active=" << (stream_tab_active_ ? "true" : "false")
            << " analysis_tab_active=" << (analysis_tab_active_ ? "true" : "false")
            << " total_packet_row_count=" << total_packet_row_count_
            << " loaded_packet_row_count=" << loaded_packet_row_count_
            << ' ' << selected_flow_diagnostics_identity(flow_model_, selected_flow_index_)
            << " elapsed=" << format_elapsed_ms(selected_flow_diagnostics::elapsed_ms(started_at))
            << ' ' << selected_flow_diagnostics::format_read_counter_delta(
                read_counters_before,
                selected_flow_diagnostics::snapshot_read_counters()
            );
        selected_flow_diagnostics::log(out.str());
    }
}

void MainController::setSelectedPacketIndex(const qulonglong packetIndex) {
    if (selected_packet_index_ == packetIndex) {
        return;
    }

    const auto started_at = std::chrono::steady_clock::now();
    const auto read_counters_before = selected_flow_diagnostics::snapshot_read_counters();

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

    if (selected_flow_diagnostics::enabled()) {
        std::ostringstream out {};
        out << "setSelectedPacketIndex packet_index=" << packetIndex
            << ' ' << selected_flow_diagnostics_identity(flow_model_, selected_flow_index_)
            << " elapsed=" << format_elapsed_ms(selected_flow_diagnostics::elapsed_ms(started_at))
            << ' ' << selected_flow_diagnostics::format_read_counter_delta(
                read_counters_before,
                selected_flow_diagnostics::snapshot_read_counters()
            );
        selected_flow_diagnostics::log(out.str());
    }
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
    packet_details_model_.setHexText(source_capture_unavailable_packet_raw_text());
    packet_details_model_.setPayloadTabTitle(QStringLiteral("Payload"));
    packet_details_model_.setPayloadText(source_capture_unavailable_packet_payload_text());
    packet_details_model_.setProtocolText(source_capture_unavailable_packet_protocol_text());
}

void MainController::showSourceUnavailableStreamDetailsPlaceholder() {
    packet_details_model_.setDetailsTitle(QStringLiteral("Stream Item Details"));
    packet_details_model_.clearStreamItemPresentation();
    packet_details_model_.setPacketDetailsText(source_capture_unavailable_stream_summary_text());
    packet_details_model_.setSummaryLayers({});
    packet_details_model_.setHexText({});
    packet_details_model_.setPayloadTabTitle(QStringLiteral("Payload"));
    packet_details_model_.setPayloadText(source_capture_unavailable_stream_payload_text());
    packet_details_model_.setProtocolText(source_capture_unavailable_stream_protocol_text());
}

void MainController::prepareSelectedFlowTcpContributionState(const std::size_t maxPacketsToScan) {
    const auto started_at = std::chrono::steady_clock::now();
    const auto read_counters_before = selected_flow_diagnostics::snapshot_read_counters();
    const auto log_result = [&](const std::string_view result,
                                const std::size_t suppressed_packet_count = 0U,
                                const double eligibility_elapsed_ms = 0.0,
                                const double retransmission_elapsed_ms = 0.0,
                                const double suppression_elapsed_ms = 0.0) {
        if (!selected_flow_diagnostics::enabled()) {
            return;
        }

        std::ostringstream out {};
        out << "prepareSelectedFlowTcpContributionState "
            << selected_flow_diagnostics_identity(flow_model_, selected_flow_index_)
            << " max_packets_to_scan=" << maxPacketsToScan
            << " result=" << result
            << " suppressed_packet_count=" << suppressed_packet_count
            << " prepared_window=" << prepared_tcp_contribution_packet_window_count_
            << " eligibility_ms=" << format_elapsed_ms(eligibility_elapsed_ms)
            << " retransmission_ms=" << format_elapsed_ms(retransmission_elapsed_ms)
            << " suppression_ms=" << format_elapsed_ms(suppression_elapsed_ms)
            << " elapsed=" << format_elapsed_ms(selected_flow_diagnostics::elapsed_ms(started_at))
            << ' ' << selected_flow_diagnostics::format_read_counter_delta(
                read_counters_before,
                selected_flow_diagnostics::snapshot_read_counters()
            );
        selected_flow_diagnostics::log(out.str());
    };

    const auto eligibility_started_at = std::chrono::steady_clock::now();

    if (selected_flow_index_ < 0 || maxPacketsToScan == 0U) {
        current_suspected_retransmission_packet_indices_.clear();
        prepared_tcp_contribution_packet_window_count_ = 0U;
        session_.clear_selected_flow_packet_cache();
        session_.clear_selected_flow_tcp_payload_suppression();
        log_result("reset", 0U, selected_flow_diagnostics::elapsed_ms(eligibility_started_at));
        return;
    }

    if (prepared_tcp_contribution_packet_window_count_ >= maxPacketsToScan) {
        log_result(
            "reuse-window",
            current_suspected_retransmission_packet_indices_.size(),
            selected_flow_diagnostics::elapsed_ms(eligibility_started_at)
        );
        return;
    }

    if (!selected_flow_uses_tcp(flow_model_, selected_flow_index_)) {
        current_suspected_retransmission_packet_indices_.clear();
        session_.clear_selected_flow_tcp_payload_suppression();
        prepared_tcp_contribution_packet_window_count_ = maxPacketsToScan;
        log_result("non-tcp-flow", 0U, selected_flow_diagnostics::elapsed_ms(eligibility_started_at));
        return;
    }

    const auto eligibility_elapsed_ms = selected_flow_diagnostics::elapsed_ms(eligibility_started_at);
    const auto flowIndex = static_cast<std::size_t>(selected_flow_index_);
    const auto retransmission_started_at = std::chrono::steady_clock::now();
    const auto suppressedPacketIndices = session_.suspected_tcp_retransmission_packet_indices(flowIndex, maxPacketsToScan);
    const auto retransmission_elapsed_ms = selected_flow_diagnostics::elapsed_ms(retransmission_started_at);
    current_suspected_retransmission_packet_indices_.clear();
    for (const auto packetIndex : suppressedPacketIndices) {
        current_suspected_retransmission_packet_indices_.insert(packetIndex);
    }

    const auto suppression_started_at = std::chrono::steady_clock::now();
    session_.set_selected_flow_tcp_payload_suppression(flowIndex, suppressedPacketIndices, maxPacketsToScan);
    const auto suppression_elapsed_ms = selected_flow_diagnostics::elapsed_ms(suppression_started_at);
    prepared_tcp_contribution_packet_window_count_ = maxPacketsToScan;
    log_result(
        "ok",
        suppressedPacketIndices.size(),
        eligibility_elapsed_ms,
        retransmission_elapsed_ms,
        suppression_elapsed_ms
    );
}

void MainController::maybeEnrichSelectedFlowServiceHint() {
    const auto started_at = std::chrono::steady_clock::now();
    const auto read_counters_before = selected_flow_diagnostics::snapshot_read_counters();
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
    if (protocolHint.compare(QStringLiteral("QUIC"), Qt::CaseInsensitive) != 0 || !serviceHint.isEmpty()) {
        return;
    }

    const auto derivedServiceHint = session_.derive_quic_service_hint_for_flow(static_cast<std::size_t>(selected_flow_index_));
    if (!derivedServiceHint.has_value() || derivedServiceHint->empty()) {
        if (selected_flow_diagnostics::enabled()) {
            std::ostringstream out {};
            out << "maybeEnrichSelectedFlowServiceHint no-change "
                << selected_flow_diagnostics_identity(flow_model_, selected_flow_index_)
                << " elapsed=" << format_elapsed_ms(selected_flow_diagnostics::elapsed_ms(started_at))
                << ' ' << selected_flow_diagnostics::format_read_counter_delta(
                    read_counters_before,
                    selected_flow_diagnostics::snapshot_read_counters()
                );
            selected_flow_diagnostics::log(out.str());
        }
        return;
    }

    flow_model_.setServiceHintForFlowIndex(selected_flow_index_, QString::fromStdString(*derivedServiceHint));
    if (selected_flow_diagnostics::enabled()) {
        std::ostringstream out {};
        out << "maybeEnrichSelectedFlowServiceHint updated "
            << selected_flow_diagnostics_identity(flow_model_, selected_flow_index_)
            << " derived_service=" << *derivedServiceHint
            << " elapsed=" << format_elapsed_ms(selected_flow_diagnostics::elapsed_ms(started_at))
            << ' ' << selected_flow_diagnostics::format_read_counter_delta(
                read_counters_before,
                selected_flow_diagnostics::snapshot_read_counters()
            );
        selected_flow_diagnostics::log(out.str());
    }
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
    const auto started_at = std::chrono::steady_clock::now();
    const auto read_counters_before = selected_flow_diagnostics::snapshot_read_counters();
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
    const auto list_started_at = std::chrono::steady_clock::now();
    auto rows = session_.list_flow_packets(static_cast<std::size_t>(selected_flow_index_), offset, batchSize);
    const auto list_elapsed_ms = selected_flow_diagnostics::elapsed_ms(list_started_at);

    if (resetRows) {
        current_suspected_retransmission_packet_indices_.clear();
        prepared_tcp_contribution_packet_window_count_ = 0U;
    }

    double cache_elapsed_ms = 0.0;
    double tcp_state_elapsed_ms = 0.0;
    double payload_enrichment_elapsed_ms = 0.0;
    if (!rows.empty()) {
        const auto cache_started_at = std::chrono::steady_clock::now();
        session_.prepare_selected_flow_packet_cache(static_cast<std::size_t>(selected_flow_index_), offset + rows.size());
        cache_elapsed_ms = selected_flow_diagnostics::elapsed_ms(cache_started_at);
        const auto tcp_state_started_at = std::chrono::steady_clock::now();
        prepareSelectedFlowTcpContributionState(offset + rows.size());
        tcp_state_elapsed_ms = selected_flow_diagnostics::elapsed_ms(tcp_state_started_at);
        const auto payload_started_at = std::chrono::steady_clock::now();
        apply_original_transport_payload_lengths(session_, rows);
        payload_enrichment_elapsed_ms = selected_flow_diagnostics::elapsed_ms(payload_started_at);
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

    if (selected_flow_diagnostics::enabled()) {
        std::ostringstream out {};
        out << "refreshSelectedFlowPackets "
            << selected_flow_diagnostics_identity(flow_model_, selected_flow_index_)
            << " reset_rows=" << (resetRows ? "true" : "false")
            << " offset=" << offset
            << " batch_size=" << batchSize
            << " returned_rows=" << rows.size()
            << " loaded_rows=" << loaded_packet_row_count_
            << " total_rows=" << total_packet_row_count_
            << " suspected_retx_count=" << current_suspected_retransmission_packet_indices_.size()
            << " list_ms=" << format_elapsed_ms(list_elapsed_ms)
            << " cache_ms=" << format_elapsed_ms(cache_elapsed_ms)
            << " tcp_state_ms=" << format_elapsed_ms(tcp_state_elapsed_ms)
            << " payload_enrichment_ms=" << format_elapsed_ms(payload_enrichment_elapsed_ms)
            << " total_elapsed=" << format_elapsed_ms(selected_flow_diagnostics::elapsed_ms(started_at))
            << ' ' << selected_flow_diagnostics::format_read_counter_delta(
                read_counters_before,
                selected_flow_diagnostics::snapshot_read_counters()
            );
        selected_flow_diagnostics::log(out.str());
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
    const auto started_at = std::chrono::steady_clock::now();
    const auto read_counters_before = selected_flow_diagnostics::snapshot_read_counters();
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
    const auto cache_started_at = std::chrono::steady_clock::now();
    session_.prepare_selected_flow_packet_cache(flowIndex, stream_packet_window_count_);
    const auto cache_elapsed_ms = selected_flow_diagnostics::elapsed_ms(cache_started_at);
    const auto tcp_state_started_at = std::chrono::steady_clock::now();
    prepareSelectedFlowTcpContributionState(stream_packet_window_count_);
    const auto tcp_state_elapsed_ms = selected_flow_diagnostics::elapsed_ms(tcp_state_started_at);
    const auto packet_number_started_at = std::chrono::steady_clock::now();
    ensureSelectedFlowPacketNumbers(stream_packet_window_count_);
    const auto packet_number_elapsed_ms = selected_flow_diagnostics::elapsed_ms(packet_number_started_at);
    const auto requestLimit = stream_item_budget_count_ + 1U;
    const bool packetBudgetExhausted = stream_packet_window_count_ < totalFlowPacketCount;
    const auto list_started_at = std::chrono::steady_clock::now();
    auto rows = session_.list_flow_stream_items_for_packet_prefix(
        flowIndex,
        stream_packet_window_count_,
        requestLimit
    );
    const auto list_elapsed_ms = selected_flow_diagnostics::elapsed_ms(list_started_at);

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

    if (selected_flow_diagnostics::enabled()) {
        std::ostringstream out {};
        out << "refreshSelectedStreamItems "
            << selected_flow_diagnostics_identity(flow_model_, selected_flow_index_)
            << " reset_rows=" << (resetRows ? "true" : "false")
            << " packet_window=" << stream_packet_window_count_
            << " item_budget=" << stream_item_budget_count_
            << " request_limit=" << requestLimit
            << " packet_budget_exhausted=" << (packetBudgetExhausted ? "true" : "false")
            << " returned_rows=" << rows.size()
            << " loaded_items=" << loaded_stream_item_count_
            << " can_load_more=" << (can_load_more_stream_items_ ? "true" : "false")
            << " cache_ms=" << format_elapsed_ms(cache_elapsed_ms)
            << " tcp_state_ms=" << format_elapsed_ms(tcp_state_elapsed_ms)
            << " packet_numbers_ms=" << format_elapsed_ms(packet_number_elapsed_ms)
            << " list_ms=" << format_elapsed_ms(list_elapsed_ms)
            << " total_elapsed=" << format_elapsed_ms(selected_flow_diagnostics::elapsed_ms(started_at))
            << ' ' << selected_flow_diagnostics::format_read_counter_delta(
                read_counters_before,
                selected_flow_diagnostics::snapshot_read_counters()
            );
        selected_flow_diagnostics::log(out.str());
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

void MainController::resetLoadedState() {
    setApplyingSession(false);
    source_capture_unavailable_notice_shown_ = false;
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
}

void MainController::applyLoadedState(const QString& path) {
    source_capture_unavailable_notice_shown_ = false;
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
    if (session_.summary().flow_count <= 30U) {
        top_endpoints_model_.refreshEndpoints({});
        top_ports_model_.refreshPorts({});
        return;
    }

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
    active_open_input_path_ = trimmedPath;
    active_open_as_index_ = asIndex;
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

    if (cancellationWon) {
        finishOpenProgress();
        setOpenErrorText({});
        setStatusText(QStringLiteral("Open cancelled."));
        return;
    }

    if (!opened) {
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

void MainController::updateSmartExportProgress(
    const qulonglong jobId,
    const SmartPerFlowExportPhase phase,
    const qulonglong packetsProcessed,
    const qulonglong totalPackets,
    const qulonglong exportedPacketsWritten
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
        progress_text = QStringLiteral("Writing output: %1 / %2 packets.")
            .arg(QString::number(packetsProcessed), total_text);
        if (exportedPacketsWritten > 0U) {
            progress_text += QStringLiteral(" Wrote %1 packets.").arg(QString::number(exportedPacketsWritten));
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
    const QString& outputPath,
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

    if (cancelled || had_cancel_request) {
        setStatusText(QStringLiteral("Smart export cancelled."));
        return;
    }

    if (!exported) {
        const auto message = errorText.isEmpty()
            ? QStringLiteral("Failed to smart-export flows.")
            : errorText;
        setStatusText(message, true);
        return;
    }

    setStatusText(QStringLiteral("Smart per-flow export completed successfully: %1").arg(outputPath));
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

    const auto started_at = std::chrono::steady_clock::now();
    const auto read_counters_before = selected_flow_diagnostics::snapshot_read_counters();

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
    const auto hexDump = session_.read_packet_hex_dump(*packet);
    const auto payloadHexDump = session_.read_packet_payload_hex_dump(*packet);
    const auto protocolText = selected_flow_quic_protocol_text_for_packet(
        session_,
        selected_flow_index_,
        packet->packet_index,
        QString::fromStdString(session_.read_packet_protocol_details_text(*packet))
    );
    const auto packetBytes = session_.read_packet_data(*packet);
    PacketChecksumSections checksum_sections {};
    if (details.has_value() && validate_selected_packet_checksums_) {
        checksum_sections = build_packet_checksum_sections(
            *details,
            *packet,
            std::span<const std::uint8_t>(packetBytes.data(), packetBytes.size())
        );
    }

    packet_details_model_.setHexText(QString::fromStdString(hexDump));

    if (details.has_value()) {
        const auto payload_lengths = resolve_transport_payload_lengths(
            *details,
            std::span<const std::uint8_t>(packetBytes.data(), packetBytes.size()),
            *packet
        );
        packet_details_model_.setPacketDetailsText(buildPacketSummary(*details, *packet, checksum_sections, payload_lengths));
        packet_details_model_.setSummaryLayers(packet_summary_layers_to_variant_list(
            session_detail::build_packet_summary_layers(*details, *packet, {
                .source_capture_accessible = true,
                .flow_packet_index = [&]() -> std::optional<std::uint64_t> {
                    const auto it = current_flow_packet_numbers_.find(packet->packet_index);
                    if (it == current_flow_packet_numbers_.end()) {
                        return std::nullopt;
                    }
                    return it->second;
                }(),
                .transport_payload_length = packet->payload_length,
                .original_transport_payload_length = payload_lengths.original_payload_length,
                .protocol_details_text = protocolText.toStdString(),
                .checksum_summary_lines = [&]() {
                    std::vector<std::string> lines {};
                    lines.reserve(static_cast<std::size_t>(checksum_sections.summary_lines.size()));
                    for (const auto& line : checksum_sections.summary_lines) {
                        lines.push_back(line.toStdString());
                    }
                    return lines;
                }(),
                .checksum_warning_lines = [&]() {
                    std::vector<std::string> lines {};
                    lines.reserve(static_cast<std::size_t>(checksum_sections.warnings.size()));
                    for (const auto& line : checksum_sections.warnings) {
                        lines.push_back(line.toStdString());
                    }
                    return lines;
                }(),
            })
        ));
        packet_details_model_.setPayloadTabTitle(packet_payload_tab_title(*details));
        packet_details_model_.setPayloadText(buildPayloadText(*details, payloadHexDump));
    } else {
        packet_details_model_.setPacketDetailsText(buildPacketSummaryFallback(*packet, checksum_sections));
        packet_details_model_.setSummaryLayers({});
        packet_details_model_.setPayloadTabTitle(QStringLiteral("Payload"));
        packet_details_model_.setPayloadText(
            !payloadHexDump.empty()
                ? QString::fromStdString(payloadHexDump)
                : QStringLiteral("Transport payload not available for this packet")
        );
    }

    packet_details_model_.setProtocolText(normalize_stream_protocol_text(protocolText));

    if (selected_flow_diagnostics::enabled()) {
        std::ostringstream out {};
        out << "reloadSelectedPacketDetails packet_index=" << selected_packet_index_
            << " details=" << (details.has_value() ? "true" : "false")
            << " packet_bytes=" << packetBytes.size()
            << " hex_chars=" << hexDump.size()
            << " payload_hex_chars=" << payloadHexDump.size()
            << ' ' << selected_flow_diagnostics_identity(flow_model_, selected_flow_index_)
            << " elapsed=" << format_elapsed_ms(selected_flow_diagnostics::elapsed_ms(started_at))
            << ' ' << selected_flow_diagnostics::format_read_counter_delta(
                read_counters_before,
                selected_flow_diagnostics::snapshot_read_counters()
            );
        selected_flow_diagnostics::log(out.str());
    }
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
    packet_details_model_.setSummaryLayers({});
    packet_details_model_.setPayloadTabTitle(stream_item_payload_tab_title(*itemIt));

    if (!itemIt->payload_hex_text.empty() || !itemIt->protocol_text.empty()) {
        packet_details_model_.setHexText({});
        packet_details_model_.setPayloadText(
            itemIt->payload_hex_text.empty()
                ? stream_payload_unavailable_text()
                : QString::fromStdString(itemIt->payload_hex_text)
        );
        const auto protocolText = itemIt->protocol_text.empty()
            ? stream_protocol_unavailable_text()
            : normalize_stream_protocol_text(QString::fromStdString(itemIt->protocol_text));
        packet_details_model_.setProtocolText(
            normalize_stream_protocol_text(
                selected_flow_quic_protocol_text_for_stream_item(session_, selected_flow_index_, *itemIt, protocolText)
            )
        );
        return;
    }

    if (itemIt->packet_indices.size() == 1U) {
        const auto packet = session_.find_packet(itemIt->packet_indices.front());
        if (packet.has_value()) {
            const auto hexDump = session_.read_packet_hex_dump(*packet);
            const auto payloadHexDump = session_.read_packet_payload_hex_dump(*packet);
            const auto protocolText = selected_flow_quic_protocol_text_for_packet(
                session_,
                selected_flow_index_,
                packet->packet_index,
                QString::fromStdString(session_.read_packet_protocol_details_text(*packet))
            );

            packet_details_model_.setHexText(QString::fromStdString(hexDump));
            if (!payloadHexDump.empty()) {
                packet_details_model_.setPayloadText(QString::fromStdString(payloadHexDump));
            } else {
                packet_details_model_.setPayloadText(stream_payload_unavailable_text());
            }
            packet_details_model_.setProtocolText(normalize_stream_protocol_text(protocolText));
            return;
        }
    }

    packet_details_model_.setHexText({});
    packet_details_model_.setPayloadText(stream_payload_unavailable_text());
    packet_details_model_.setProtocolText(stream_protocol_unavailable_text());
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

QString MainController::chooseDirectory(const QString& title) const {
    return QFileDialog::getExistingDirectory(
        nullptr,
        title,
        last_directory_path_,
        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks
    );
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































