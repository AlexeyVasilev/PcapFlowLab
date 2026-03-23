#include "ui/app/MainController.h"

#include <filesystem>
#include <limits>

#include <QStringList>

namespace pfl {

namespace {

constexpr qulonglong kInvalidPacketSelection = std::numeric_limits<qulonglong>::max();

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

QString buildPacketSummary(const PacketDetails& details) {
    QStringList lines {};
    lines.push_back(QStringLiteral("Packet: %1").arg(details.packet_index));
    lines.push_back(QStringLiteral("Captured Length: %1").arg(details.captured_length));
    lines.push_back(QStringLiteral("Original Length: %1").arg(details.original_length));

    if (details.has_ethernet) {
        lines.push_back(QStringLiteral("EtherType: %1").arg(formatHex16(details.ethernet.ether_type)));
    }

    if (details.has_vlan) {
        lines.push_back(QStringLiteral("VLAN Tags: %1").arg(details.vlan_tags.size()));
        for (std::size_t index = 0; index < details.vlan_tags.size(); ++index) {
            const auto& tag = details.vlan_tags[index];
            lines.push_back(
                QStringLiteral("VLAN[%1] TCI: %2 Encapsulated EtherType: %3")
                    .arg(index)
                    .arg(tag.tci)
                    .arg(formatHex16(tag.encapsulated_ether_type))
            );
        }
    }

    if (details.has_arp) {
        lines.push_back(QStringLiteral("ARP Opcode: %1").arg(details.arp.opcode));
        lines.push_back(QStringLiteral("ARP Sender IPv4: %1").arg(formatIpv4Address(details.arp.sender_ipv4)));
        lines.push_back(QStringLiteral("ARP Target IPv4: %1").arg(formatIpv4Address(details.arp.target_ipv4)));
    }

    if (details.has_ipv4) {
        lines.push_back(QStringLiteral("IPv4 Source: %1").arg(formatIpv4Address(details.ipv4.src_addr)));
        lines.push_back(QStringLiteral("IPv4 Destination: %1").arg(formatIpv4Address(details.ipv4.dst_addr)));
        lines.push_back(QStringLiteral("IPv4 Protocol: %1").arg(formatProtocol(details.ipv4.protocol)));
    }

    if (details.has_ipv6) {
        lines.push_back(QStringLiteral("IPv6 Source: %1").arg(formatIpv6Address(details.ipv6.src_addr)));
        lines.push_back(QStringLiteral("IPv6 Destination: %1").arg(formatIpv6Address(details.ipv6.dst_addr)));
        lines.push_back(QStringLiteral("IPv6 Next Header: %1").arg(formatProtocol(details.ipv6.next_header)));
    }

    if (details.has_tcp) {
        lines.push_back(QStringLiteral("TCP Source Port: %1").arg(details.tcp.src_port));
        lines.push_back(QStringLiteral("TCP Destination Port: %1").arg(details.tcp.dst_port));
        lines.push_back(QStringLiteral("TCP Flags: %1").arg(formatTcpFlags(details.tcp.flags)));
    }

    if (details.has_udp) {
        lines.push_back(QStringLiteral("UDP Source Port: %1").arg(details.udp.src_port));
        lines.push_back(QStringLiteral("UDP Destination Port: %1").arg(details.udp.dst_port));
    }

    if (details.has_icmp) {
        lines.push_back(QStringLiteral("ICMP Type: %1").arg(details.icmp.type));
        lines.push_back(QStringLiteral("ICMP Code: %1").arg(details.icmp.code));
    }

    if (details.has_icmpv6) {
        lines.push_back(QStringLiteral("ICMPv6 Type: %1").arg(details.icmpv6.type));
        lines.push_back(QStringLiteral("ICMPv6 Code: %1").arg(details.icmpv6.code));
    }

    return lines.join(QLatin1Char('\n'));
}

}  // namespace

MainController::MainController(QObject* parent)
    : QObject(parent)
    , selected_packet_index_(kInvalidPacketSelection) {
}

QString MainController::currentInputPath() const {
    return current_input_path_;
}

bool MainController::hasCapture() const noexcept {
    return session_.has_capture();
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

bool MainController::openCaptureFile(const QString& path) {
    return openPath(path, false);
}

bool MainController::openIndexFile(const QString& path) {
    return openPath(path, true);
}

bool MainController::openPath(const QString& path, const bool asIndex) {
    const QString trimmed_path = path.trimmed();
    if (trimmed_path.isEmpty()) {
        current_input_path_.clear();
        session_ = {};
        flow_model_.clear();
        packet_model_.clear();
        clearPacketSelection();
        emit stateChanged();
        return false;
    }

    const std::filesystem::path filesystem_path = std::filesystem::path {trimmed_path.toStdWString()};
    const bool opened = asIndex ? session_.load_index(filesystem_path) : session_.open_capture(filesystem_path);

    if (!opened) {
        current_input_path_.clear();
        session_ = {};
        flow_model_.clear();
        packet_model_.clear();
        clearPacketSelection();
        emit stateChanged();
        return false;
    }

    current_input_path_ = trimmed_path;
    flow_model_.refresh(session_.list_flows());
    packet_model_.clear();
    clearPacketSelection();
    emit stateChanged();
    return true;
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

    if (!details.has_value()) {
        packet_details_model_.clear();
        emit selectedPacketIndexChanged();
        return;
    }

    packet_details_model_.setPacketDetailsText(buildPacketSummary(*details));
    packet_details_model_.setHexText(QString::fromStdString(hex));
    emit selectedPacketIndexChanged();
}

void MainController::clearPacketSelection() {
    const bool selectionChanged = selected_packet_index_ != kInvalidPacketSelection;
    selected_packet_index_ = kInvalidPacketSelection;
    packet_details_model_.clear();

    if (selectionChanged) {
        emit selectedPacketIndexChanged();
    }
}

}  // namespace pfl
