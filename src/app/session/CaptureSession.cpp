#include "app/session/CaptureSession.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <array>
#include <iostream>
#include <iomanip>
#include <limits>
#include <map>
#include <span>
#include <sstream>
#include <string_view>

#include "../../../core/open_context.h"
#include "core/debug_logging.h"
#include "core/index/CaptureIndex.h"
#include "core/index/CaptureIndexReader.h"
#include "core/index/CaptureIndexWriter.h"
#include "core/reassembly/ReassemblyService.h"
#include "core/io/CaptureFilePacketReader.h"
#include "core/services/CaptureImporter.h"
#include "core/services/DnsPacketProtocolAnalyzer.h"
#include "core/services/FlowExportService.h"
#include "core/services/FlowAnalysisService.h"
#include "core/services/FlowHintService.h"
#include "core/services/HexDumpService.h"
#include "core/services/HttpPacketProtocolAnalyzer.h"
#include "core/services/PacketDetailsService.h"
#include "core/services/PacketPayloadService.h"
#include "core/services/PerfOpenLogger.h"
#include "core/services/TlsPacketProtocolAnalyzer.h"

namespace pfl {

namespace {

struct ListedConnectionRef {
    FlowAddressFamily family {FlowAddressFamily::ipv4};
    const ConnectionV4* ipv4 {nullptr};
    const ConnectionV6* ipv6 {nullptr};
};

std::string format_ipv4_address(std::uint32_t address);
std::string format_ipv6_address(const std::array<std::uint8_t, 16>& address);
std::string format_endpoint(const EndpointKeyV4& endpoint);
std::string format_endpoint(const EndpointKeyV6& endpoint);

std::uintmax_t file_size_or_zero(const std::filesystem::path& path) {
    std::error_code error {};
    const auto size = std::filesystem::file_size(path, error);
    return error ? 0U : size;
}

OpenFailureInfo fallback_open_failure(const char* reason) {
    OpenFailureInfo failure {};
    failure.reason = reason;
    return failure;
}

std::string format_open_failure_message(const OpenFailureInfo& failure) {
    std::ostringstream builder {};
    builder << "Open failed";

    if (failure.has_file_offset) {
        builder << " at offset " << failure.file_offset;
    }

    if (failure.has_packet_index) {
        if (failure.has_file_offset) {
            builder << " (packet " << failure.packet_index << ')';
        } else {
            builder << " at packet " << failure.packet_index;
        }
    }

    if (failure.bytes_processed != 0U || failure.packets_processed != 0U) {
        builder << " after ";
        bool wrote_part = false;
        if (failure.bytes_processed != 0U) {
            builder << failure.bytes_processed << " bytes";
            wrote_part = true;
        }
        if (failure.packets_processed != 0U) {
            if (wrote_part) {
                builder << " and ";
            }
            builder << failure.packets_processed << " packets";
        }
    }

    if (!failure.reason.empty()) {
        builder << ": " << failure.reason;
    }

    return builder.str();
}

std::string build_open_failure_message(const OpenContext* ctx, const OpenFailureInfo& fallback_failure) {
    if (ctx != nullptr && ctx->failure.has_details()) {
        return format_open_failure_message(ctx->failure);
    }

    return format_open_failure_message(fallback_failure);
}

void log_open_result(
    const PerfOpenLogger& logger,
    const PerfOpenOperationType operation_type,
    const std::filesystem::path& input_path,
    const bool success,
    const std::chrono::steady_clock::time_point started_at,
    const CaptureSession& session
) {
    if (!logger.enabled()) {
        return;
    }

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started_at
    );
    logger.append(PerfOpenRecord {
        .operation_type = operation_type,
        .input_path = input_path,
        .input_kind = PerfOpenLogger::detect_input_kind(input_path),
        .file_size_bytes = file_size_or_zero(input_path),
        .success = success,
        .elapsed_ms = static_cast<std::uint64_t>(elapsed.count()),
        .packet_count = session.summary().packet_count,
        .flow_count = session.summary().flow_count,
        .total_bytes = session.summary().total_bytes,
        .opened_from_index = session.opened_from_index(),
        .has_source_capture = session.has_source_capture(),
    });
}

std::uint64_t packet_count(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->packet_count : connection.ipv6->packet_count;
}

std::uint64_t total_bytes(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->total_bytes : connection.ipv6->total_bytes;
}

ProtocolId protocol_id(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->key.protocol : connection.ipv6->key.protocol;
}

FlowProtocolHint protocol_hint(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->protocol_hint : connection.ipv6->protocol_hint;
}

bool has_port_443(const ListedConnectionRef& connection) noexcept {
    if (connection.family == FlowAddressFamily::ipv4) {
        return connection.ipv4->key.first.port == 443U || connection.ipv4->key.second.port == 443U;
    }

    return connection.ipv6->key.first.port == 443U || connection.ipv6->key.second.port == 443U;
}

FlowProtocolHint effective_protocol_hint(const ListedConnectionRef& connection, const AnalysisSettings& settings) noexcept {
    const auto confirmed_hint = protocol_hint(connection);
    if (confirmed_hint != FlowProtocolHint::unknown) {
        return confirmed_hint;
    }

    if (!settings.use_possible_tls_quic || !has_port_443(connection)) {
        return FlowProtocolHint::unknown;
    }

    switch (protocol_id(connection)) {
    case ProtocolId::tcp:
        return FlowProtocolHint::possible_tls;
    case ProtocolId::udp:
        return FlowProtocolHint::possible_quic;
    default:
        return FlowProtocolHint::unknown;
    }
}
std::string protocol_text(const ProtocolId protocol) {
    switch (protocol) {
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
        return "unknown";
    }
}

bool listed_connection_less(const ListedConnectionRef& left, const ListedConnectionRef& right) noexcept {
    if (total_bytes(left) != total_bytes(right)) {
        return total_bytes(left) > total_bytes(right);
    }

    if (packet_count(left) != packet_count(right)) {
        return packet_count(left) > packet_count(right);
    }

    if (left.family != right.family) {
        return left.family < right.family;
    }

    if (left.family == FlowAddressFamily::ipv4) {
        return left.ipv4->key < right.ipv4->key;
    }

    return left.ipv6->key < right.ipv6->key;
}

std::vector<ListedConnectionRef> list_connections(const CaptureState& state) {
    std::vector<ListedConnectionRef> connections {};

    const auto ipv4_connections = state.ipv4_connections.list();
    const auto ipv6_connections = state.ipv6_connections.list();
    connections.reserve(ipv4_connections.size() + ipv6_connections.size());

    for (const auto* connection : ipv4_connections) {
        connections.push_back(ListedConnectionRef {
            .family = FlowAddressFamily::ipv4,
            .ipv4 = connection,
        });
    }

    for (const auto* connection : ipv6_connections) {
        connections.push_back(ListedConnectionRef {
            .family = FlowAddressFamily::ipv6,
            .ipv6 = connection,
        });
    }

    std::sort(connections.begin(), connections.end(), listed_connection_less);
    return connections;
}

void add_protocol_stats(ProtocolStats& stats, const ListedConnectionRef& connection) noexcept {
    ++stats.flow_count;
    stats.packet_count += packet_count(connection);
    stats.total_bytes += total_bytes(connection);
}

std::vector<PacketRef> collect_packets(const ConnectionV4& connection) {
    std::vector<PacketRef> packets {};
    packets.reserve(connection.flow_a.packets.size() + connection.flow_b.packets.size());
    packets.insert(packets.end(), connection.flow_a.packets.begin(), connection.flow_a.packets.end());
    packets.insert(packets.end(), connection.flow_b.packets.begin(), connection.flow_b.packets.end());
    std::sort(packets.begin(), packets.end(), [](const PacketRef& left, const PacketRef& right) {
        return left.packet_index < right.packet_index;
    });
    return packets;
}

std::vector<PacketRef> collect_packets(const ConnectionV6& connection) {
    std::vector<PacketRef> packets {};
    packets.reserve(connection.flow_a.packets.size() + connection.flow_b.packets.size());
    packets.insert(packets.end(), connection.flow_a.packets.begin(), connection.flow_a.packets.end());
    packets.insert(packets.end(), connection.flow_b.packets.begin(), connection.flow_b.packets.end());
    std::sort(packets.begin(), packets.end(), [](const PacketRef& left, const PacketRef& right) {
        return left.packet_index < right.packet_index;
    });
    return packets;
}

FlowRow make_flow_row(std::size_t index, const ListedConnectionRef& connection, const AnalysisSettings& settings) {
    const auto hint = effective_protocol_hint(connection, settings);
    const auto hint_text = hint == FlowProtocolHint::unknown ? std::string {} : std::string {flow_protocol_hint_text(hint)};

    if (connection.family == FlowAddressFamily::ipv4) {
        const auto& key = connection.ipv4->key;
        return FlowRow {
            .index = index,
            .family = FlowAddressFamily::ipv4,
            .key = key,
            .protocol_text = protocol_text(key.protocol),
            .protocol_hint = hint_text,
            .service_hint = connection.ipv4->service_hint,
            .has_fragmented_packets = connection.ipv4->has_fragmented_packets,
            .fragmented_packet_count = connection.ipv4->fragmented_packet_count,
            .address_a = format_ipv4_address(key.first.addr),
            .port_a = key.first.port,
            .endpoint_a = format_endpoint(key.first),
            .address_b = format_ipv4_address(key.second.addr),
            .port_b = key.second.port,
            .endpoint_b = format_endpoint(key.second),
            .packet_count = connection.ipv4->packet_count,
            .total_bytes = connection.ipv4->total_bytes,
        };
    }

    const auto& key = connection.ipv6->key;
    return FlowRow {
        .index = index,
        .family = FlowAddressFamily::ipv6,
        .key = key,
        .protocol_text = protocol_text(key.protocol),
        .protocol_hint = hint_text,
        .service_hint = connection.ipv6->service_hint,
        .has_fragmented_packets = connection.ipv6->has_fragmented_packets,
        .fragmented_packet_count = connection.ipv6->fragmented_packet_count,
        .address_a = format_ipv6_address(key.first.addr),
        .port_a = key.first.port,
        .endpoint_a = format_endpoint(key.first),
        .address_b = format_ipv6_address(key.second.addr),
        .port_b = key.second.port,
        .endpoint_b = format_endpoint(key.second),
        .packet_count = connection.ipv6->packet_count,
        .total_bytes = connection.ipv6->total_bytes,
    };
}
std::string format_packet_timestamp(const PacketRef& packet) {
    const auto seconds_of_day = packet.ts_sec % 86400U;
    const auto hours = seconds_of_day / 3600U;
    const auto minutes = (seconds_of_day % 3600U) / 60U;
    const auto seconds = seconds_of_day % 60U;

    std::ostringstream timestamp {};
    timestamp << std::setfill('0')
              << std::setw(2) << hours << ':'
              << std::setw(2) << minutes << ':'
              << std::setw(2) << seconds << '.'
              << std::setw(6) << packet.ts_usec;
    return timestamp.str();
}

std::string format_tcp_flags_text(const std::uint8_t flags) {
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

    std::ostringstream builder {};
    bool first = true;
    for (const auto& flag : names) {
        if ((flags & flag.mask) == 0U) {
            continue;
        }

        if (!first) {
            builder << '|';
        }

        builder << flag.name;
        first = false;
    }

    return first ? std::string {} : builder.str();
}

std::string format_ipv4_address(const std::uint32_t address) {
    std::ostringstream builder {};
    builder << ((address >> 24U) & 0xFFU) << '.'
            << ((address >> 16U) & 0xFFU) << '.'
            << ((address >> 8U) & 0xFFU) << '.'
            << (address & 0xFFU);
    return builder.str();
}

std::string format_ipv6_address(const std::array<std::uint8_t, 16>& address) {
    std::ostringstream builder {};
    builder << std::hex << std::setfill('0');

    for (std::size_t index = 0; index < 8; ++index) {
        if (index > 0) {
            builder << ':';
        }

        const auto word = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(address[index * 2U]) << 8U) |
            static_cast<std::uint16_t>(address[index * 2U + 1U])
        );
        builder << std::setw(4) << word;
    }

    return builder.str();
}

std::string format_endpoint(const EndpointKeyV4& endpoint) {
    std::ostringstream builder {};
    builder << format_ipv4_address(endpoint.addr) << ':' << endpoint.port;
    return builder.str();
}

std::string format_endpoint(const EndpointKeyV6& endpoint) {
    std::ostringstream builder {};
    builder << '[' << format_ipv6_address(endpoint.addr) << "]:" << endpoint.port;
    return builder.str();
}

std::string format_ipv4_address(const std::array<std::uint8_t, 4>& address) {
    std::ostringstream builder {};
    builder << static_cast<unsigned>(address[0]) << '.'
            << static_cast<unsigned>(address[1]) << '.'
            << static_cast<unsigned>(address[2]) << '.'
            << static_cast<unsigned>(address[3]);
    return builder.str();
}

std::optional<std::string> build_basic_protocol_details_text(const PacketDetails& details) {
    std::ostringstream builder {};

    if (details.has_arp) {
        builder << "ARP\n"
                << "Opcode: " << details.arp.opcode << '\n'
                << "Sender IPv4: " << format_ipv4_address(details.arp.sender_ipv4) << '\n'
                << "Target IPv4: " << format_ipv4_address(details.arp.target_ipv4);
        return builder.str();
    }

    if (details.has_icmp) {
        builder << "ICMP\n"
                << "Type: " << static_cast<unsigned>(details.icmp.type) << '\n'
                << "Code: " << static_cast<unsigned>(details.icmp.code);
        if (details.has_ipv4) {
            builder << '\n'
                    << "Source: " << format_ipv4_address(details.ipv4.src_addr) << '\n'
                    << "Destination: " << format_ipv4_address(details.ipv4.dst_addr);
        }
        return builder.str();
    }

    if (details.has_icmpv6) {
        builder << "ICMPv6\n"
                << "Type: " << static_cast<unsigned>(details.icmpv6.type) << '\n'
                << "Code: " << static_cast<unsigned>(details.icmpv6.code);
        if (details.has_ipv6) {
            builder << '\n'
                    << "Source: " << format_ipv6_address(details.ipv6.src_addr) << '\n'
                    << "Destination: " << format_ipv6_address(details.ipv6.dst_addr);
        }
        return builder.str();
    }

    return std::nullopt;
}

constexpr std::string_view kFastModeProtocolDetailsMessage = "Protocol details are only available in Deep mode.";
constexpr std::string_view kNoProtocolDetailsMessage = "No protocol-specific details available for this packet.";
constexpr std::string_view kUnavailableProtocolDetailsMessage = "Protocol details unavailable for this packet.";
constexpr std::string_view kFragmentedProtocolDetailsMessage = "Protocol details are unavailable for fragmented packets until reassembly is implemented.";
constexpr std::string_view kDirectionAToB = "A\xE2\x86\x92" "B";
constexpr std::string_view kDirectionBToA = "B\xE2\x86\x92" "A";

PacketRow make_packet_row(const PacketRef& packet, const std::string_view direction_text) {
    return PacketRow {
        .row_number = 0,
        .packet_index = packet.packet_index,
        .direction_text = std::string {direction_text},
        .timestamp_text = format_packet_timestamp(packet),
        .captured_length = packet.captured_length,
        .original_length = packet.original_length,
        .payload_length = packet.payload_length,
        .is_ip_fragmented = packet.is_ip_fragmented,
        .tcp_flags_text = format_tcp_flags_text(packet.tcp_flags),
    };
}

struct StreamPacketCandidate {
    PacketRef packet {};
    std::string_view direction_text {};
    ProtocolId protocol {ProtocolId::unknown};
};

constexpr std::size_t kTlsRecordHeaderSize = 5U;

bool contains_text(const std::string_view text, const std::string_view needle) noexcept {
    return text.find(needle) != std::string_view::npos;
}

std::uint16_t read_be16(std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                      static_cast<std::uint16_t>(bytes[offset + 1U]));
}

bool looks_like_tls_record_prefix(std::span<const std::uint8_t> payload, const std::size_t offset = 0U) noexcept {
    if (offset > payload.size() || payload.size() - offset < kTlsRecordHeaderSize) {
        return false;
    }

    const auto content_type = payload[offset];
    if (content_type < 20U || content_type > 23U) {
        return false;
    }

    return payload[offset + 1U] == 0x03U && payload[offset + 2U] <= 0x04U;
}

std::optional<std::size_t> tls_record_size(std::span<const std::uint8_t> payload, const std::size_t offset = 0U) noexcept {
    if (!looks_like_tls_record_prefix(payload, offset)) {
        return std::nullopt;
    }

    const auto record_body_length = static_cast<std::size_t>(read_be16(payload, offset + 3U));
    const auto record_size = kTlsRecordHeaderSize + record_body_length;
    if (payload.size() - offset < record_size) {
        return std::nullopt;
    }

    return record_size;
}

std::string tls_record_version_text(const std::uint16_t version) {
    switch (version) {
    case 0x0301U:
        return "TLS 1.0 (0x0301)";
    case 0x0302U:
        return "TLS 1.1 (0x0302)";
    case 0x0303U:
        return "TLS 1.2 (0x0303)";
    case 0x0304U:
        return "TLS 1.3 (0x0304)";
    default: {
        std::ostringstream builder {};
        builder << "0x" << std::hex << version;
        return builder.str();
    }
    }
}

const char* tls_record_type_text(const std::uint8_t content_type) noexcept {
    switch (content_type) {
    case 20U:
        return "ChangeCipherSpec";
    case 21U:
        return "Alert";
    case 22U:
        return "Handshake";
    case 23U:
        return "ApplicationData";
    default:
        return "Unknown";
    }
}

const char* tls_handshake_type_text(const std::uint8_t handshake_type) noexcept {
    switch (handshake_type) {
    case 1U:
        return "ClientHello";
    case 2U:
        return "ServerHello";
    case 4U:
        return "NewSessionTicket";
    case 8U:
        return "EncryptedExtensions";
    case 11U:
        return "Certificate";
    case 12U:
        return "ServerKeyExchange";
    case 13U:
        return "CertificateRequest";
    case 14U:
        return "ServerHelloDone";
    case 15U:
        return "CertificateVerify";
    case 16U:
        return "ClientKeyExchange";
    case 20U:
        return "Finished";
    default:
        return "Unknown";
    }
}

std::string fallback_stream_label(const ProtocolId protocol) {
    switch (protocol) {
    case ProtocolId::tcp:
        return "TCP Payload";
    case ProtocolId::udp:
        return "UDP Payload";
    default:
        return "Payload";
    }
}

std::string tls_stream_label(std::span<const std::uint8_t> record_bytes) {
    if (record_bytes.size() < kTlsRecordHeaderSize) {
        return "TLS Payload";
    }

    const auto content_type = record_bytes[0];
    switch (content_type) {
    case 20U:
        return "TLS ChangeCipherSpec";
    case 22U:
        if (record_bytes.size() >= kTlsRecordHeaderSize + 4U) {
            switch (record_bytes[kTlsRecordHeaderSize]) {
            case 1U:
                return "TLS ClientHello";
            case 2U:
                return "TLS ServerHello";
            default:
                return "TLS Handshake";
            }
        }
        return "TLS Handshake";
    case 23U:
        return "TLS AppData";
    default:
        return "TLS Record";
    }
}

std::string tls_record_protocol_text(std::span<const std::uint8_t> record_bytes) {
    if (record_bytes.size() < kTlsRecordHeaderSize) {
        return "TLS\n  Record details unavailable for this stream item.";
    }

    const auto content_type = record_bytes[0];
    const auto version = read_be16(record_bytes, 1);
    const auto record_length = static_cast<std::size_t>(read_be16(record_bytes, 3));

    std::ostringstream text {};
    text << "TLS\n"
         << "  Record Type: " << tls_record_type_text(content_type) << "\n"
         << "  Record Version: " << tls_record_version_text(version) << "\n"
         << "  Record Length: " << record_length;

    if (content_type == 22U && record_bytes.size() >= kTlsRecordHeaderSize + 4U) {
        const auto handshake_type = record_bytes[kTlsRecordHeaderSize];
        text << "\n"
             << "  Handshake Type: " << tls_handshake_type_text(handshake_type);
    }

    return text.str();
}

StreamItemRow make_stream_item_row(
    const std::uint64_t stream_item_index,
    const std::string_view direction_text,
    const std::string& label,
    const std::size_t byte_count,
    const std::vector<std::uint64_t>& packet_indices,
    const std::string& payload_hex_text = {},
    const std::string& protocol_text = {}
) {
    return StreamItemRow {
        .stream_item_index = stream_item_index,
        .direction_text = std::string {direction_text},
        .label = label,
        .byte_count = static_cast<std::uint32_t>(byte_count),
        .packet_count = static_cast<std::uint32_t>(packet_indices.size()),
        .packet_indices = packet_indices,
        .payload_hex_text = payload_hex_text,
        .protocol_text = protocol_text,
    };
}

StreamItemRow make_stream_item_row(
    const std::uint64_t stream_item_index,
    const std::string_view direction_text,
    const std::string& label,
    const std::size_t byte_count,
    const PacketRef& packet,
    const std::string& payload_hex_text = {},
    const std::string& protocol_text = {}
) {
    return make_stream_item_row(
        stream_item_index,
        direction_text,
        label,
        byte_count,
        std::vector<std::uint64_t> {packet.packet_index},
        payload_hex_text,
        protocol_text
    );
}

bool append_tls_stream_items(
    std::vector<StreamItemRow>& rows,
    const StreamPacketCandidate& candidate,
    std::span<const std::uint8_t> payload_bytes
) {
    if (!looks_like_tls_record_prefix(payload_bytes)) {
        return false;
    }

    HexDumpService hex_dump_service {};
    std::size_t offset = 0;
    bool emitted_any = false;

    while (offset < payload_bytes.size()) {
        if (!looks_like_tls_record_prefix(payload_bytes, offset)) {
            const auto trailing = payload_bytes.subspan(offset);
            if (!trailing.empty()) {
                rows.push_back(make_stream_item_row(
                    static_cast<std::uint64_t>(rows.size() + 1U),
                    candidate.direction_text,
                    "TLS Payload (partial)",
                    trailing.size(),
                    candidate.packet,
                    hex_dump_service.format(trailing),
                    "TLS\n  Remaining bytes do not form a complete TLS record in this packet."
                ));
            }
            return true;
        }

        const auto record_size = tls_record_size(payload_bytes, offset);
        if (!record_size.has_value()) {
            const auto trailing = payload_bytes.subspan(offset);
            rows.push_back(make_stream_item_row(
                static_cast<std::uint64_t>(rows.size() + 1U),
                candidate.direction_text,
                "TLS Record Fragment (partial)",
                trailing.size(),
                candidate.packet,
                hex_dump_service.format(trailing),
                "TLS\n  Record header is present but the full TLS record body is not available in this packet."
            ));
            return true;
        }

        const auto record_bytes = payload_bytes.subspan(offset, *record_size);
        rows.push_back(make_stream_item_row(
            static_cast<std::uint64_t>(rows.size() + 1U),
            candidate.direction_text,
            tls_stream_label(record_bytes),
            record_bytes.size(),
            candidate.packet,
            hex_dump_service.format(record_bytes),
            tls_record_protocol_text(record_bytes)
        ));
        emitted_any = true;
        offset += *record_size;
    }

    return emitted_any;
}
bool has_reassembly_flag(const ReassemblyResult& result, const ReassemblyQualityFlag flag) noexcept {
    return (result.quality_flags & static_cast<std::uint32_t>(flag)) != 0U;
}


struct ReassembledPayloadChunk {
    std::uint64_t packet_index {0};
    std::size_t byte_count {0};
};

std::optional<std::vector<ReassembledPayloadChunk>> build_reassembled_payload_chunks(
    const CaptureSession& session,
    const ReassemblyResult& result
) {
    std::vector<ReassembledPayloadChunk> chunks {};
    chunks.reserve(result.packet_indices.size());

    PacketPayloadService payload_service {};
    std::size_t consumed_bytes = 0;

    for (const auto packet_index : result.packet_indices) {
        if (consumed_bytes >= result.bytes.size()) {
            break;
        }

        const auto packet = session.find_packet(packet_index);
        if (!packet.has_value()) {
            return std::nullopt;
        }

        const auto packet_bytes = session.read_packet_data(*packet);
        if (packet_bytes.empty()) {
            return std::nullopt;
        }

        const auto payload_bytes = payload_service.extract_transport_payload(packet_bytes, packet->data_link_type);
        if (payload_bytes.empty()) {
            return std::nullopt;
        }

        const auto remaining_bytes = result.bytes.size() - consumed_bytes;
        const auto chunk_size = std::min<std::size_t>(payload_bytes.size(), remaining_bytes);
        if (chunk_size == 0U) {
            continue;
        }

        chunks.push_back(ReassembledPayloadChunk {
            .packet_index = packet_index,
            .byte_count = chunk_size,
        });
        consumed_bytes += chunk_size;
    }

    if (consumed_bytes != result.bytes.size()) {
        return std::nullopt;
    }

    return chunks;
}

std::vector<std::uint64_t> consume_reassembled_packet_indices(
    const std::vector<ReassembledPayloadChunk>& chunks,
    const std::size_t byte_count,
    std::size_t& chunk_index,
    std::size_t& chunk_offset
) {
    std::vector<std::uint64_t> packet_indices {};
    std::size_t remaining_bytes = byte_count;

    while (remaining_bytes > 0U && chunk_index < chunks.size()) {
        const auto& chunk = chunks[chunk_index];
        if (packet_indices.empty() || packet_indices.back() != chunk.packet_index) {
            packet_indices.push_back(chunk.packet_index);
        }

        const auto chunk_remaining = chunk.byte_count - chunk_offset;
        const auto consumed_here = std::min(remaining_bytes, chunk_remaining);
        remaining_bytes -= consumed_here;
        chunk_offset += consumed_here;

        if (chunk_offset >= chunk.byte_count) {
            ++chunk_index;
            chunk_offset = 0U;
        }
    }

    return packet_indices;
}

std::string limited_quality_tls_protocol_text(const bool record_fragment) {
    if (record_fragment) {
        return "TLS\n  Reassembled bytes do not contain a complete TLS record in this direction.";
    }

    return "TLS\n  Reassembled bytes suggest a TLS record, but stream reconstruction quality is limited for this direction.";
}

std::string_view bytes_as_text(std::span<const std::uint8_t> bytes) {
    return std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

bool ascii_iequals(const char left, const char right) noexcept {
    return std::tolower(static_cast<unsigned char>(left)) == std::tolower(static_cast<unsigned char>(right));
}

bool starts_with_ascii_case_insensitive(const std::string_view value, const std::string_view prefix) noexcept {
    if (value.size() < prefix.size()) {
        return false;
    }

    for (std::size_t index = 0; index < prefix.size(); ++index) {
        if (!ascii_iequals(value[index], prefix[index])) {
            return false;
        }
    }

    return true;
}

std::string trim_ascii(const std::string_view value) {
    std::size_t begin = 0U;
    std::size_t end = value.size();

    while (begin < end && (value[begin] == ' ' || value[begin] == '\t' || value[begin] == '\r' || value[begin] == '\n')) {
        ++begin;
    }

    while (end > begin && (value[end - 1U] == ' ' || value[end - 1U] == '\t' || value[end - 1U] == '\r' || value[end - 1U] == '\n')) {
        --end;
    }

    return std::string {value.substr(begin, end - begin)};
}

bool is_http_token_char(const char value) noexcept {
    return std::isalnum(static_cast<unsigned char>(value)) != 0 || value == '-' || value == '_' || value == '.' || value == '/';
}

bool is_plausible_host_char(const char value) noexcept {
    return std::isalnum(static_cast<unsigned char>(value)) != 0 || value == '.' || value == '-' || value == '_';
}

bool is_plausible_host(const std::string_view value) noexcept {
    if (value.empty()) {
        return false;
    }

    for (const auto character : value) {
        if (!is_plausible_host_char(character)) {
            return false;
        }
    }

    return true;
}

std::size_t http_line_end(const std::string_view text, const std::size_t offset) noexcept {
    const auto crlf = text.find("\r\n", offset);
    const auto lf = text.find('\n', offset);
    if (crlf == std::string_view::npos) {
        return lf;
    }
    if (lf == std::string_view::npos) {
        return crlf;
    }
    return (crlf < lf) ? crlf : lf;
}

std::size_t http_next_line_offset(const std::string_view text, const std::size_t end) noexcept {
    if (end == std::string_view::npos || end >= text.size()) {
        return text.size();
    }

    if (text[end] == '\r' && (end + 1U) < text.size() && text[end + 1U] == '\n') {
        return end + 2U;
    }

    return end + 1U;
}

std::optional<std::size_t> http_header_block_size(std::string_view payload_text, const std::size_t offset) noexcept {
    if (offset >= payload_text.size()) {
        return std::nullopt;
    }

    const auto subtext = payload_text.substr(offset);
    const auto crlfcrlf = subtext.find("\r\n\r\n");
    const auto lflf = subtext.find("\n\n");
    if (crlfcrlf == std::string_view::npos && lflf == std::string_view::npos) {
        return std::nullopt;
    }

    if (crlfcrlf != std::string_view::npos && (lflf == std::string_view::npos || crlfcrlf < lflf)) {
        return crlfcrlf + 4U;
    }

    return lflf + 2U;
}

bool looks_like_http_request_line(const std::string_view line) noexcept {
    constexpr std::array<std::string_view, 9> methods {
        "GET ", "POST ", "PUT ", "HEAD ", "OPTIONS ", "DELETE ", "PATCH ", "CONNECT ", "TRACE ",
    };

    for (const auto method : methods) {
        if (line.starts_with(method)) {
            return true;
        }
    }

    return false;
}

bool looks_like_http_response_line(const std::string_view line) noexcept {
    return line.starts_with("HTTP/1.");
}

std::optional<std::string> extract_http_host_header(const std::string_view headers) {
    std::size_t offset = 0U;
    while (offset < headers.size()) {
        const auto end = http_line_end(headers, offset);
        const auto line = headers.substr(offset, ((end == std::string_view::npos) ? headers.size() : end) - offset);
        if (line.empty()) {
            break;
        }

        if (starts_with_ascii_case_insensitive(line, "Host:")) {
            const auto host = trim_ascii(line.substr(5U));
            if (is_plausible_host(host)) {
                return host;
            }
            return std::nullopt;
        }

        if (end == std::string_view::npos) {
            break;
        }
        offset = http_next_line_offset(headers, end);
    }

    return std::nullopt;
}

std::optional<std::string> extract_http_header_value(
    const std::string_view headers,
    const std::string_view header_name
) {
    std::size_t offset = 0U;
    while (offset < headers.size()) {
        const auto end = http_line_end(headers, offset);
        const auto line = headers.substr(offset, ((end == std::string_view::npos) ? headers.size() : end) - offset);
        if (line.empty()) {
            break;
        }

        const auto separator = line.find(':');
        if (separator != std::string_view::npos) {
            const auto name = trim_ascii(line.substr(0U, separator));
            if (starts_with_ascii_case_insensitive(name, header_name) && name.size() == header_name.size()) {
                const auto value = trim_ascii(line.substr(separator + 1U));
                if (!value.empty()) {
                    return value;
                }
                return std::nullopt;
            }
        }

        if (end == std::string_view::npos) {
            break;
        }
        offset = http_next_line_offset(headers, end);
    }

    return std::nullopt;
}

struct ParsedHttpHeaderBlock {
    std::size_t size {0U};
    std::string label {};
    std::string protocol_text {};
};

std::optional<ParsedHttpHeaderBlock> parse_http_header_block(
    std::span<const std::uint8_t> payload_bytes,
    const std::size_t offset
) {
    const auto payload_text = bytes_as_text(payload_bytes);
    const auto header_size = http_header_block_size(payload_text, offset);
    if (!header_size.has_value()) {
        return std::nullopt;
    }

    const auto header_text = payload_text.substr(offset, *header_size);
    const auto first_line_end = http_line_end(header_text, 0U);
    const auto first_line = header_text.substr(0U, (first_line_end == std::string_view::npos) ? header_text.size() : first_line_end);
    if (first_line.empty()) {
        return std::nullopt;
    }

    std::ostringstream text {};
    text << "HTTP\n";

    if (looks_like_http_request_line(first_line)) {
        const auto method_end = first_line.find(' ');
        if (method_end == std::string_view::npos) {
            return std::nullopt;
        }

        const auto path_start = method_end + 1U;
        const auto path_end = first_line.find(' ', path_start);
        if (path_end == std::string_view::npos || path_end <= path_start) {
            return std::nullopt;
        }

        const auto method = first_line.substr(0U, method_end);
        const auto path = first_line.substr(path_start, path_end - path_start);
        const auto version = first_line.substr(path_end + 1U);
        if (!version.starts_with("HTTP/1.") || path.empty()) {
            return std::nullopt;
        }

        for (const auto character : method) {
            if (!std::isupper(static_cast<unsigned char>(character))) {
                return std::nullopt;
            }
        }
        for (const auto character : version) {
            if (!(is_http_token_char(character) || character == ' ')) {
                return std::nullopt;
            }
        }

        text << "  Message Type: Request\n"
             << "  Method: " << method << "\n"
             << "  Path: " << path << "\n"
             << "  Version: " << version;

        const auto host = extract_http_host_header(header_text.substr(http_next_line_offset(header_text, first_line_end)));
        if (host.has_value()) {
            text << "\n"
                 << "  Host: " << *host;
        }

        const auto method_text = std::string {method};
        const auto path_text = std::string {path};
        return ParsedHttpHeaderBlock {
            .size = *header_size,
            .label = method_text.empty() || path_text.empty()
                ? "HTTP Request"
                : ("HTTP " + method_text + " " + path_text),
            .protocol_text = text.str(),
        };
    }

    if (looks_like_http_response_line(first_line)) {
        const auto version_end = first_line.find(' ');
        if (version_end == std::string_view::npos) {
            return std::nullopt;
        }

        const auto code_start = version_end + 1U;
        if (code_start + 3U > first_line.size()) {
            return std::nullopt;
        }

        const auto version = first_line.substr(0U, version_end);
        const auto code = first_line.substr(code_start, 3U);
        for (const auto character : code) {
            if (!std::isdigit(static_cast<unsigned char>(character))) {
                return std::nullopt;
            }
        }

        text << "  Message Type: Response\n"
             << "  Version: " << version << "\n"
             << "  Status Code: " << code;

        std::string reason_text {};
        const auto reason_start = code_start + 3U;
        if (reason_start < first_line.size() && first_line[reason_start] == ' ') {
            const auto reason = trim_ascii(first_line.substr(reason_start + 1U));
            if (!reason.empty()) {
                reason_text = reason;
                text << "\n"
                     << "  Reason: " << reason;
            }
        }

        const auto headers_text = header_text.substr(http_next_line_offset(header_text, first_line_end));
        if (const auto content_type = extract_http_header_value(headers_text, "Content-Type"); content_type.has_value()) {
            text << "\n"
                 << "  Content-Type: " << *content_type;
        }
        if (const auto content_length = extract_http_header_value(headers_text, "Content-Length"); content_length.has_value()) {
            text << "\n"
                 << "  Content-Length: " << *content_length;
        }

        const auto code_text = std::string {code};
        return ParsedHttpHeaderBlock {
            .size = *header_size,
            .label = code_text.empty()
                ? "HTTP Response"
                : (reason_text.empty() ? ("HTTP " + code_text) : ("HTTP " + code_text + " " + reason_text)),
            .protocol_text = text.str(),
        };
    }

    return std::nullopt;
}

std::optional<std::string_view> find_protocol_detail_value(
    const std::string_view protocol_text,
    const std::string_view key
) noexcept {
    const auto marker = std::string {"  "} + std::string {key} + ": ";
    const auto marker_pos = protocol_text.find(marker);
    if (marker_pos == std::string_view::npos) {
        return std::nullopt;
    }

    const auto value_start = marker_pos + marker.size();
    const auto value_end = protocol_text.find('\n', value_start);
    const auto value = protocol_text.substr(value_start, (value_end == std::string_view::npos) ? (protocol_text.size() - value_start) : (value_end - value_start));
    if (value.empty()) {
        return std::nullopt;
    }

    return value;
}

std::string http_stream_label_from_protocol_text(const std::string_view protocol_text) {
    if (contains_text(protocol_text, "Message Type: Request")) {
        const auto method = find_protocol_detail_value(protocol_text, "Method");
        const auto path = find_protocol_detail_value(protocol_text, "Path");
        if (method.has_value() && path.has_value()) {
            return "HTTP " + std::string {*method} + " " + std::string {*path};
        }
        return "HTTP Request";
    }

    if (contains_text(protocol_text, "Message Type: Response")) {
        const auto status_code = find_protocol_detail_value(protocol_text, "Status Code");
        const auto reason = find_protocol_detail_value(protocol_text, "Reason");
        if (status_code.has_value()) {
            if (reason.has_value()) {
                return "HTTP " + std::string {*status_code} + " " + std::string {*reason};
            }
            return "HTTP " + std::string {*status_code};
        }
        return "HTTP Response";
    }

    return "HTTP Payload";
}
std::string limited_quality_http_protocol_text() {
    return "HTTP\n  Reassembled bytes do not contain a complete HTTP header block in this direction.";
}

bool append_http_stream_items_from_reassembly(
    std::vector<StreamItemRow>& rows,
    const CaptureSession& session,
    const std::size_t flow_index,
    const std::string_view direction_text,
    const Direction direction
) {
    const auto result = session.reassemble_flow_direction(ReassemblyRequest {
        .flow_index = flow_index,
        .direction = direction,
        .max_packets = 256U,
        .max_bytes = 256U * 1024U,
    });
    if (!result.has_value() || result->bytes.empty()) {
        return false;
    }

    if (has_reassembly_flag(*result, ReassemblyQualityFlag::may_contain_transport_gaps)) {
        return false;
    }

    const auto payload_bytes = std::span<const std::uint8_t>(result->bytes.data(), result->bytes.size());
    const auto payload_text = bytes_as_text(payload_bytes);
    const auto chunks = build_reassembled_payload_chunks(session, *result);
    if (!chunks.has_value() || chunks->empty()) {
        return false;
    }

    HexDumpService hex_dump_service {};
    std::size_t offset = 0U;
    std::size_t chunk_index = 0U;
    std::size_t chunk_offset = 0U;
    bool emitted_any = false;

    while (offset < payload_bytes.size()) {
        const auto parsed = parse_http_header_block(payload_bytes, offset);
        if (!parsed.has_value()) {
            if (offset == 0U) {
                return false;
            }

            const auto trailing = payload_bytes.subspan(offset);
            if (!trailing.empty()) {
                const auto packet_indices = consume_reassembled_packet_indices(*chunks, trailing.size(), chunk_index, chunk_offset);
                rows.push_back(make_stream_item_row(
                    static_cast<std::uint64_t>(rows.size() + 1U),
                    direction_text,
                    "HTTP Payload (partial)",
                    trailing.size(),
                    packet_indices,
                    hex_dump_service.format(trailing),
                    limited_quality_http_protocol_text()
                ));
            }
            return true;
        }

        const auto block_bytes = payload_bytes.subspan(offset, parsed->size);
        const auto packet_indices = consume_reassembled_packet_indices(*chunks, block_bytes.size(), chunk_index, chunk_offset);
        rows.push_back(make_stream_item_row(
            static_cast<std::uint64_t>(rows.size() + 1U),
            direction_text,
            parsed->label,
            block_bytes.size(),
            packet_indices,
            hex_dump_service.format(block_bytes),
            parsed->protocol_text
        ));
        emitted_any = true;
        offset += parsed->size;

        if (offset < payload_text.size()) {
            const auto next_line_end = http_line_end(payload_text, offset);
            const auto next_line = payload_text.substr(offset, ((next_line_end == std::string_view::npos) ? payload_text.size() : next_line_end) - offset);
            if (!looks_like_http_request_line(next_line) && !looks_like_http_response_line(next_line)) {
                const auto trailing = payload_bytes.subspan(offset);
                if (!trailing.empty()) {
                    const auto packet_indices = consume_reassembled_packet_indices(*chunks, trailing.size(), chunk_index, chunk_offset);
                    rows.push_back(make_stream_item_row(
                        static_cast<std::uint64_t>(rows.size() + 1U),
                        direction_text,
                        "HTTP Payload (partial)",
                        trailing.size(),
                        packet_indices,
                        hex_dump_service.format(trailing),
                        limited_quality_http_protocol_text()
                    ));
                }
                return true;
            }
        }
    }

    return emitted_any;
}

bool append_tls_stream_items_from_reassembly(
    std::vector<StreamItemRow>& rows,
    const CaptureSession& session,
    const std::size_t flow_index,
    const std::string_view direction_text,
    const Direction direction
) {
    const auto result = session.reassemble_flow_direction(ReassemblyRequest {
        .flow_index = flow_index,
        .direction = direction,
        .max_packets = 256U,
        .max_bytes = 256U * 1024U,
    });
    if (!result.has_value() || result->bytes.empty()) {
        return false;
    }

    const auto payload_bytes = std::span<const std::uint8_t>(result->bytes.data(), result->bytes.size());
    if (!looks_like_tls_record_prefix(payload_bytes)) {
        return false;
    }

    const auto chunks = build_reassembled_payload_chunks(session, *result);
    if (!chunks.has_value() || chunks->empty()) {
        return false;
    }

    const bool limited_quality = has_reassembly_flag(*result, ReassemblyQualityFlag::may_contain_transport_gaps);
    HexDumpService hex_dump_service {};
    std::size_t offset = 0U;
    std::size_t chunk_index = 0U;
    std::size_t chunk_offset = 0U;
    bool emitted_any = false;

    while (offset < payload_bytes.size()) {
        if (!looks_like_tls_record_prefix(payload_bytes, offset)) {
            const auto trailing = payload_bytes.subspan(offset);
            if (!trailing.empty()) {
                const auto packet_indices = consume_reassembled_packet_indices(*chunks, trailing.size(), chunk_index, chunk_offset);
                rows.push_back(make_stream_item_row(
                    static_cast<std::uint64_t>(rows.size() + 1U),
                    direction_text,
                    "TLS Payload (partial)",
                    trailing.size(),
                    packet_indices,
                    hex_dump_service.format(trailing),
                    limited_quality_tls_protocol_text(false)
                ));
            }
            return true;
        }

        const auto record_size = tls_record_size(payload_bytes, offset);
        if (!record_size.has_value()) {
            const auto trailing = payload_bytes.subspan(offset);
            const auto packet_indices = consume_reassembled_packet_indices(*chunks, trailing.size(), chunk_index, chunk_offset);
            rows.push_back(make_stream_item_row(
                static_cast<std::uint64_t>(rows.size() + 1U),
                direction_text,
                "TLS Record Fragment (partial)",
                trailing.size(),
                packet_indices,
                hex_dump_service.format(trailing),
                limited_quality_tls_protocol_text(true)
            ));
            return true;
        }

        const auto record_bytes = payload_bytes.subspan(offset, *record_size);
        const auto packet_indices = consume_reassembled_packet_indices(*chunks, record_bytes.size(), chunk_index, chunk_offset);
        rows.push_back(make_stream_item_row(
            static_cast<std::uint64_t>(rows.size() + 1U),
            direction_text,
            limited_quality ? std::string {"TLS Payload"} : tls_stream_label(record_bytes),
            record_bytes.size(),
            packet_indices,
            hex_dump_service.format(record_bytes),
            limited_quality ? limited_quality_tls_protocol_text(false) : tls_record_protocol_text(record_bytes)
        ));
        emitted_any = true;
        offset += *record_size;
    }

    return emitted_any;
}

std::string classify_stream_label(
    const std::vector<std::uint8_t>& packet_bytes,
    const std::uint32_t data_link_type,
    const ProtocolId protocol,
    const bool deep_protocol_details_enabled
) {
    if (deep_protocol_details_enabled) {
        TlsPacketProtocolAnalyzer tls_analyzer {};
        if (const auto tls_details = tls_analyzer.analyze(packet_bytes, data_link_type); tls_details.has_value()) {
            const auto text = std::string_view(*tls_details);
            if (contains_text(text, "Handshake Type: ClientHello")) {
                return "TLS ClientHello";
            }
            if (contains_text(text, "Handshake Type: ServerHello")) {
                return "TLS ServerHello";
            }
            if (contains_text(text, "Record Type: ChangeCipherSpec")) {
                return "TLS ChangeCipherSpec";
            }
            if (contains_text(text, "Record Type: ApplicationData")) {
                return "TLS AppData";
            }
            if (contains_text(text, "Record Type: Handshake")) {
                return "TLS Handshake";
            }
            return "TLS Payload";
        }

        HttpPacketProtocolAnalyzer http_analyzer {};
        if (const auto http_details = http_analyzer.analyze(packet_bytes, data_link_type); http_details.has_value()) {
            return http_stream_label_from_protocol_text(*http_details);
        }

        DnsPacketProtocolAnalyzer dns_analyzer {};
        if (const auto dns_details = dns_analyzer.analyze(packet_bytes, data_link_type); dns_details.has_value()) {
            const auto text = std::string_view(*dns_details);
            if (contains_text(text, "Message Type: Query")) {
                return "DNS Query";
            }
            if (contains_text(text, "Message Type: Response")) {
                return "DNS Response";
            }
            return "DNS Payload";
        }
    }

    return fallback_stream_label(protocol);
}

std::optional<PacketRef> find_packet_in_connection(const ConnectionV4& connection, std::uint64_t packet_index) {
    for (const auto& packet : connection.flow_a.packets) {
        if (packet.packet_index == packet_index) {
            return packet;
        }
    }

    for (const auto& packet : connection.flow_b.packets) {
        if (packet.packet_index == packet_index) {
            return packet;
        }
    }

    return std::nullopt;
}

std::optional<PacketRef> find_packet_in_connection(const ConnectionV6& connection, std::uint64_t packet_index) {
    for (const auto& packet : connection.flow_a.packets) {
        if (packet.packet_index == packet_index) {
            return packet;
        }
    }

    for (const auto& packet : connection.flow_b.packets) {
        if (packet.packet_index == packet_index) {
            return packet;
        }
    }

    return std::nullopt;
}

template <typename Connection>
std::size_t connection_packet_count(const Connection& connection) noexcept {
    return connection.flow_a.packets.size() + connection.flow_b.packets.size();
}

template <typename Connection>
void append_connection_stream_items_bounded(
    std::vector<StreamItemRow>& rows,
    const CaptureSession& session,
    const Connection& connection,
    const ProtocolId flow_protocol,
    const std::size_t target_count,
    const std::size_t max_packets_to_scan,
    const bool deep_protocol_details_enabled,
    const bool skip_direction_a,
    const bool skip_direction_b
) {
    PacketPayloadService payload_service {};
    std::size_t index_a = 0U;
    std::size_t index_b = 0U;
    std::size_t scanned_packets = 0U;

    while ((index_a < connection.flow_a.packets.size() || index_b < connection.flow_b.packets.size()) &&
           rows.size() < target_count &&
           scanned_packets < max_packets_to_scan) {
        const bool use_a = index_b >= connection.flow_b.packets.size() ||
            (index_a < connection.flow_a.packets.size() &&
             connection.flow_a.packets[index_a].packet_index <= connection.flow_b.packets[index_b].packet_index);

        const auto& packet = use_a ? connection.flow_a.packets[index_a++] : connection.flow_b.packets[index_b++];
        ++scanned_packets;
        const auto direction_text = use_a ? kDirectionAToB : kDirectionBToA;

        if ((use_a && skip_direction_a) || (!use_a && skip_direction_b)) {
            continue;
        }

        if (packet.payload_length == 0U) {
            continue;
        }

        const auto packet_bytes = session.read_packet_data(packet);
        if (packet_bytes.empty()) {
            continue;
        }

        const auto payload_bytes = payload_service.extract_transport_payload(packet_bytes, packet.data_link_type);
        if (payload_bytes.empty()) {
            continue;
        }

        const auto candidate = StreamPacketCandidate {
            .packet = packet,
            .direction_text = direction_text,
            .protocol = flow_protocol,
        };

        if (flow_protocol == ProtocolId::tcp) {
            const auto payload_span = std::span<const std::uint8_t>(payload_bytes.data(), payload_bytes.size());
            if (append_tls_stream_items(rows, candidate, payload_span)) {
                continue;
            }
        }

        const auto label = classify_stream_label(packet_bytes, packet.data_link_type, flow_protocol, deep_protocol_details_enabled);
        rows.push_back(make_stream_item_row(
            static_cast<std::uint64_t>(rows.size() + 1U),
            direction_text,
            label,
            payload_bytes.size(),
            packet
        ));
    }
}

template <typename Connection>
std::vector<PacketRow> slice_connection_packets(
    const Connection& connection,
    const std::size_t offset,
    const std::size_t limit
) {
    if (limit == 0U) {
        return {};
    }

    std::vector<PacketRow> rows {};
    const auto total = connection_packet_count(connection);
    if (offset >= total) {
        return rows;
    }

    const auto target = std::min(total, offset + limit);
    rows.reserve(target - offset);

    std::size_t emitted = 0U;
    std::size_t row_number = 0U;
    std::size_t index_a = 0U;
    std::size_t index_b = 0U;

    while ((index_a < connection.flow_a.packets.size() || index_b < connection.flow_b.packets.size()) && row_number < target) {
        const bool use_a = index_b >= connection.flow_b.packets.size() ||
            (index_a < connection.flow_a.packets.size() &&
             connection.flow_a.packets[index_a].packet_index <= connection.flow_b.packets[index_b].packet_index);

        const auto& packet = use_a ? connection.flow_a.packets[index_a++] : connection.flow_b.packets[index_b++];
        const auto direction = use_a ? kDirectionAToB : kDirectionBToA;

        if (row_number >= offset) {
            auto row = make_packet_row(packet, direction);
            row.row_number = row_number + 1U;
            rows.push_back(std::move(row));
            ++emitted;
            if (emitted >= limit) {
                break;
            }
        }

        ++row_number;
    }

    return rows;
}

}  // namespace

void CaptureSession::reset_runtime_state() noexcept {
    capture_path_.clear();
    source_capture_path_.clear();
    source_info_ = {};
    state_ = {};
    import_mode_ = ImportMode::fast;
    analysis_settings_ = {};
    deep_protocol_details_enabled_ = false;
    opened_from_index_ = false;
    has_loaded_state_ = false;
    last_open_error_text_.clear();
}

bool CaptureSession::open_capture(const std::filesystem::path& path) {
    return open_capture(path, CaptureImportOptions {}, nullptr);
}

bool CaptureSession::open_capture(const std::filesystem::path& path, OpenContext* ctx) {
    return open_capture(path, CaptureImportOptions {}, ctx);
}

bool CaptureSession::open_capture(const std::filesystem::path& path, const CaptureImportOptions& options) {
    return open_capture(path, options, nullptr);
}

bool CaptureSession::open_capture(const std::filesystem::path& path, const CaptureImportOptions& options, OpenContext* ctx) {
    last_open_error_text_.clear();
    partial_open_ = false;
    partial_open_failure_ = {};
    OpenContext local_ctx {};
    OpenContext* effective_ctx = (ctx != nullptr) ? ctx : &local_ctx;
    effective_ctx->clear_failure();
    debug::log_if<debug::kDebugOpen>([&]() {
        std::clog << "open_capture: " << path.string() << " mode="
                  << ((options.mode == ImportMode::deep) ? "deep" : "fast") << '\n';
    });
    const auto started_at = std::chrono::steady_clock::now();
    PerfOpenLogger perf_logger {};
    const auto operation_type = (options.mode == ImportMode::deep)
        ? PerfOpenOperationType::capture_deep
        : PerfOpenOperationType::capture_fast;

    CaptureImporter importer {};
    CaptureState imported_state {};
    const auto import_result = importer.import_capture_result(path, imported_state, options, effective_ctx);

    if (import_result == CaptureImportResult::failure) {
        debug::log_if<debug::kDebugOpen>([&]() {
            std::clog << "open_capture failed: " << path.string() << '\n';
        });
        const auto failureText = build_open_failure_message(effective_ctx, fallback_open_failure("capture import failed"));
        reset_runtime_state();
        last_open_error_text_ = failureText;
        log_open_result(perf_logger, operation_type, path, false, started_at, *this);
        return false;
    }

    capture_path_ = path;
    source_capture_path_ = path;
    state_ = imported_state;
    import_mode_ = options.mode;
    analysis_settings_ = options.settings;
    deep_protocol_details_enabled_ = (options.mode == ImportMode::deep);
    opened_from_index_ = false;
    has_loaded_state_ = true;
    partial_open_ = (import_result == CaptureImportResult::partial_success_with_warning);
    partial_open_failure_ = effective_ctx->failure;
    source_info_ = {};
    if (!read_capture_source_info(path, source_info_)) {
        source_info_.capture_path = path;
    }

    debug::log_if<debug::kDebugOpen>([&]() {
        std::clog << (partial_open_ ? "open_capture partial: " : "open_capture succeeded: ") << path.string() << '\n';
    });
    log_open_result(perf_logger, operation_type, path, true, started_at, *this);
    return true;
}

bool CaptureSession::open_input(const std::filesystem::path& path) {
    return open_input(path, nullptr);
}

bool CaptureSession::open_input(const std::filesystem::path& path, OpenContext* ctx) {
    if (looks_like_index_file(path)) {
        return load_index(path, ctx);
    }

    return open_capture(path, ctx);
}

bool CaptureSession::save_index(const std::filesystem::path& index_path) const {
    if (partial_open_ || !has_source_capture()) {
        return false;
    }

    CaptureIndexWriter writer {};
    return writer.write(index_path, state_, capture_path_);
}

bool CaptureSession::load_index(const std::filesystem::path& index_path) {
    return load_index(index_path, nullptr);
}

bool CaptureSession::load_index(const std::filesystem::path& index_path, OpenContext* ctx) {
    last_open_error_text_.clear();
    OpenContext local_ctx {};
    OpenContext* effective_ctx = (ctx != nullptr) ? ctx : &local_ctx;
    effective_ctx->clear_failure();
    debug::log_if<debug::kDebugIndexLoad>([&]() {
        std::clog << "load_index: " << index_path.string() << '\n';
    });
    const auto started_at = std::chrono::steady_clock::now();
    PerfOpenLogger perf_logger {};

    CaptureIndexReader reader {};
    CaptureState loaded_state {};
    std::filesystem::path loaded_capture_path {};
    CaptureSourceInfo loaded_source_info {};

    if (!reader.read(index_path, loaded_state, loaded_capture_path, &loaded_source_info, effective_ctx)) {
        debug::log_if<debug::kDebugIndexLoad>([&]() {
            std::clog << "load_index failed: " << index_path.string() << '\n';
        });
        const auto fallback_failure = reader.last_error().has_details()
            ? reader.last_error()
            : fallback_open_failure("index read failed");
        const auto failureText = build_open_failure_message(effective_ctx, fallback_failure);
        reset_runtime_state();
        last_open_error_text_ = failureText;
        log_open_result(perf_logger, PerfOpenOperationType::index_load, index_path, false, started_at, *this);
        return false;
    }

    capture_path_.clear();
    source_capture_path_ = loaded_capture_path;
    source_info_ = loaded_source_info;
    state_ = loaded_state;
    import_mode_ = ImportMode::fast;
    analysis_settings_ = {};
    deep_protocol_details_enabled_ = false;
    opened_from_index_ = true;
    has_loaded_state_ = true;
    partial_open_ = false;
    partial_open_failure_ = {};

    if (validate_capture_source(source_info_)) {
        capture_path_ = source_info_.capture_path;
    }

    debug::log_if<debug::kDebugIndexLoad>([&]() {
        std::clog << "load_index succeeded: " << index_path.string() << '\n';
    });
    log_open_result(perf_logger, PerfOpenOperationType::index_load, index_path, true, started_at, *this);
    return true;
}

bool CaptureSession::has_capture() const noexcept {
    return has_loaded_state_;
}

bool CaptureSession::has_source_capture() const noexcept {
    return !capture_path_.empty();
}

bool CaptureSession::opened_from_index() const noexcept {
    return opened_from_index_;
}

bool CaptureSession::is_partial_open() const noexcept {
    return partial_open_;
}

const OpenFailureInfo& CaptureSession::partial_open_failure() const noexcept {
    return partial_open_failure_;
}

const std::string& CaptureSession::last_open_error_text() const noexcept {
    return last_open_error_text_;
}

bool CaptureSession::attach_source_capture(const std::filesystem::path& path) {
    if (!opened_from_index_) {
        return false;
    }

    if (!validate_capture_source(source_info_, path)) {
        return false;
    }

    capture_path_ = path;
    source_capture_path_ = path;
    source_info_.capture_path = path;
    return true;
}

const std::filesystem::path& CaptureSession::capture_path() const noexcept {
    return source_capture_path_;
}

const std::filesystem::path& CaptureSession::attached_source_capture_path() const noexcept {
    return capture_path_;
}

const std::filesystem::path& CaptureSession::expected_source_capture_path() const noexcept {
    return source_capture_path_;
}

const CaptureSummary& CaptureSession::summary() const noexcept {
    return state_.summary;
}

CaptureProtocolSummary CaptureSession::protocol_summary() const noexcept {
    CaptureProtocolSummary summary {};

    for (const auto& connection : list_connections(state_)) {
        if (connection.family == FlowAddressFamily::ipv4) {
            add_protocol_stats(summary.ipv4, connection);
        } else {
            add_protocol_stats(summary.ipv6, connection);
        }

        switch (protocol_id(connection)) {
        case ProtocolId::tcp:
            add_protocol_stats(summary.tcp, connection);
            break;
        case ProtocolId::udp:
            add_protocol_stats(summary.udp, connection);
            break;
        default:
            add_protocol_stats(summary.other, connection);
            break;
        }

        switch (effective_protocol_hint(connection, analysis_settings_)) {
        case FlowProtocolHint::http:
            add_protocol_stats(summary.hint_http, connection);
            break;
        case FlowProtocolHint::tls:
            add_protocol_stats(summary.hint_tls, connection);
            break;
        case FlowProtocolHint::dns:
            add_protocol_stats(summary.hint_dns, connection);
            break;
        case FlowProtocolHint::quic:
            add_protocol_stats(summary.hint_quic, connection);
            break;
        case FlowProtocolHint::ssh:
            add_protocol_stats(summary.hint_ssh, connection);
            break;
        case FlowProtocolHint::stun:
            add_protocol_stats(summary.hint_stun, connection);
            break;
        case FlowProtocolHint::bittorrent:
            add_protocol_stats(summary.hint_bittorrent, connection);
            break;
        case FlowProtocolHint::dhcp:
            add_protocol_stats(summary.hint_dhcp, connection);
            break;
        case FlowProtocolHint::mdns:
            add_protocol_stats(summary.hint_mdns, connection);
            break;
        case FlowProtocolHint::smtp:
            add_protocol_stats(summary.hint_smtp, connection);
            add_protocol_stats(summary.hint_mail_protocols, connection);
            break;
        case FlowProtocolHint::pop3:
            add_protocol_stats(summary.hint_pop3, connection);
            add_protocol_stats(summary.hint_mail_protocols, connection);
            break;
        case FlowProtocolHint::imap:
            add_protocol_stats(summary.hint_imap, connection);
            add_protocol_stats(summary.hint_mail_protocols, connection);
            break;
        case FlowProtocolHint::possible_tls:
            add_protocol_stats(summary.hint_possible_tls, connection);
            break;
        case FlowProtocolHint::possible_quic:
            add_protocol_stats(summary.hint_possible_quic, connection);
            break;
        case FlowProtocolHint::unknown:
        default:
            add_protocol_stats(summary.hint_unknown, connection);
            break;
        }
    }

    return summary;
}

void CaptureSession::set_analysis_settings(const AnalysisSettings& settings) noexcept {
    analysis_settings_ = settings;
}

QuicRecognitionStats CaptureSession::quic_recognition_stats() const noexcept {
    QuicRecognitionStats stats {};

    const auto connections = list_connections(state_);
    for (const auto& connection : connections) {
        const auto protocol_hint = (connection.family == FlowAddressFamily::ipv4)
            ? connection.ipv4->protocol_hint
            : connection.ipv6->protocol_hint;
        if (protocol_hint != FlowProtocolHint::quic) {
            continue;
        }

        ++stats.total_flows;

        const auto& service_hint = (connection.family == FlowAddressFamily::ipv4)
            ? connection.ipv4->service_hint
            : connection.ipv6->service_hint;
        if (service_hint.empty()) {
            ++stats.without_sni;
        } else {
            ++stats.with_sni;
        }

        const auto version_hint = (connection.family == FlowAddressFamily::ipv4)
            ? connection.ipv4->quic_version
            : connection.ipv6->quic_version;
        switch (version_hint) {
        case QuicVersionHint::v1:
            ++stats.version_v1;
            break;
        case QuicVersionHint::draft29:
            ++stats.version_draft29;
            break;
        case QuicVersionHint::v2:
            ++stats.version_v2;
            break;
        case QuicVersionHint::unknown:
        default:
            ++stats.version_unknown;
            break;
        }
    }

#ifndef NDEBUG
    const auto sni_sum = stats.with_sni + stats.without_sni;
    const auto version_sum = stats.version_v1 + stats.version_draft29 + stats.version_v2 + stats.version_unknown;
    assert(sni_sum == stats.total_flows);
    assert(version_sum == stats.total_flows);
#endif

    return stats;
}

TlsRecognitionStats CaptureSession::tls_recognition_stats() const noexcept {
    TlsRecognitionStats stats {};

    const auto connections = list_connections(state_);
    for (const auto& connection : connections) {
        const auto protocol_hint = (connection.family == FlowAddressFamily::ipv4)
            ? connection.ipv4->protocol_hint
            : connection.ipv6->protocol_hint;
        if (protocol_hint != FlowProtocolHint::tls) {
            continue;
        }

        ++stats.total_flows;

        const auto& service_hint = (connection.family == FlowAddressFamily::ipv4)
            ? connection.ipv4->service_hint
            : connection.ipv6->service_hint;
        if (service_hint.empty()) {
            ++stats.without_sni;
        } else {
            ++stats.with_sni;
        }

        const auto version_hint = (connection.family == FlowAddressFamily::ipv4)
            ? connection.ipv4->tls_version
            : connection.ipv6->tls_version;
        switch (version_hint) {
        case TlsVersionHint::tls12:
            ++stats.version_tls12;
            break;
        case TlsVersionHint::tls13:
            ++stats.version_tls13;
            break;
        case TlsVersionHint::unknown:
        default:
            ++stats.version_unknown;
            break;
        }
    }

#ifndef NDEBUG
    const auto sni_sum = stats.with_sni + stats.without_sni;
    const auto version_sum = stats.version_tls12 + stats.version_tls13 + stats.version_unknown;
    assert(sni_sum == stats.total_flows);
    assert(version_sum == stats.total_flows);
#endif

    return stats;
}

CaptureTopSummary CaptureSession::top_summary(const std::size_t limit) const {
    std::map<std::string, TopEndpointRow> endpoints {};
    std::map<std::uint16_t, TopPortRow> ports {};

    for (const auto& connection : list_connections(state_)) {
        const auto connection_packets = packet_count(connection);
        const auto connection_bytes = total_bytes(connection);

        if (connection.family == FlowAddressFamily::ipv4) {
            const auto& key = connection.ipv4->key;

            for (const auto& endpointText : {format_endpoint(key.first), format_endpoint(key.second)}) {
                auto& row = endpoints[endpointText];
                row.endpoint = endpointText;
                row.packet_count += connection_packets;
                row.total_bytes += connection_bytes;
            }

            for (const auto port : {key.first.port, key.second.port}) {
                if (port == 0U) {
                    continue;
                }

                auto& row = ports[port];
                row.port = port;
                row.packet_count += connection_packets;
                row.total_bytes += connection_bytes;
            }
        } else {
            const auto& key = connection.ipv6->key;

            for (const auto& endpointText : {format_endpoint(key.first), format_endpoint(key.second)}) {
                auto& row = endpoints[endpointText];
                row.endpoint = endpointText;
                row.packet_count += connection_packets;
                row.total_bytes += connection_bytes;
            }

            for (const auto port : {key.first.port, key.second.port}) {
                if (port == 0U) {
                    continue;
                }

                auto& row = ports[port];
                row.port = port;
                row.packet_count += connection_packets;
                row.total_bytes += connection_bytes;
            }
        }
    }

    CaptureTopSummary summary {};
    summary.endpoints_by_bytes.reserve(endpoints.size());
    summary.ports_by_bytes.reserve(ports.size());

    for (const auto& [_, row] : endpoints) {
        summary.endpoints_by_bytes.push_back(row);
    }

    for (const auto& [_, row] : ports) {
        summary.ports_by_bytes.push_back(row);
    }

    std::sort(summary.endpoints_by_bytes.begin(), summary.endpoints_by_bytes.end(), [](const TopEndpointRow& left, const TopEndpointRow& right) {
        if (left.total_bytes != right.total_bytes) {
            return left.total_bytes > right.total_bytes;
        }
        if (left.packet_count != right.packet_count) {
            return left.packet_count > right.packet_count;
        }
        return left.endpoint < right.endpoint;
    });

    std::sort(summary.ports_by_bytes.begin(), summary.ports_by_bytes.end(), [](const TopPortRow& left, const TopPortRow& right) {
        if (left.total_bytes != right.total_bytes) {
            return left.total_bytes > right.total_bytes;
        }
        if (left.packet_count != right.packet_count) {
            return left.packet_count > right.packet_count;
        }
        return left.port < right.port;
    });

    if (summary.endpoints_by_bytes.size() > limit) {
        summary.endpoints_by_bytes.resize(limit);
    }

    if (summary.ports_by_bytes.size() > limit) {
        summary.ports_by_bytes.resize(limit);
    }

    return summary;
}

std::vector<std::uint8_t> CaptureSession::read_packet_data(const PacketRef& packet) const {
    if (!has_source_capture()) {
        return {};
    }

    CaptureFilePacketReader reader {capture_path_};
    if (!reader.is_open()) {
        return {};
    }

    return reader.read_packet_data(packet);
}

std::optional<PacketDetails> CaptureSession::read_packet_details(const PacketRef& packet) const {
    const auto bytes = read_packet_data(packet);
    if (bytes.empty()) {
        return std::nullopt;
    }

    PacketDetailsService service {};
    return service.decode(bytes, packet);
}

std::string CaptureSession::read_packet_hex_dump(const PacketRef& packet) const {
    const auto bytes = read_packet_data(packet);
    if (bytes.empty()) {
        return {};
    }

    HexDumpService service {};
    return service.format(bytes);
}

std::string CaptureSession::read_packet_payload_hex_dump(const PacketRef& packet) const {
    const auto bytes = read_packet_data(packet);
    if (bytes.empty()) {
        return {};
    }

    PacketPayloadService payload_service {};
    const auto payload_bytes = payload_service.extract_transport_payload(bytes, packet.data_link_type);

    HexDumpService hex_dump_service {};
    return hex_dump_service.format(payload_bytes);
}

std::string CaptureSession::read_packet_protocol_details_text(const PacketRef& packet) const {
    if (!deep_protocol_details_enabled_) {
        return std::string {kFastModeProtocolDetailsMessage};
    }

    if (packet.is_ip_fragmented) {
        return std::string {kFragmentedProtocolDetailsMessage};
    }

    const auto bytes = read_packet_data(packet);
    if (bytes.empty()) {
        return std::string {kUnavailableProtocolDetailsMessage};
    }

    TlsPacketProtocolAnalyzer tls_analyzer {};
    if (const auto tls_details = tls_analyzer.analyze(bytes, packet.data_link_type); tls_details.has_value()) {
        return *tls_details;
    }

    DnsPacketProtocolAnalyzer dns_analyzer {};
    if (const auto dns_details = dns_analyzer.analyze(bytes, packet.data_link_type); dns_details.has_value()) {
        return *dns_details;
    }

    HttpPacketProtocolAnalyzer http_analyzer {};
    if (const auto http_details = http_analyzer.analyze(bytes, packet.data_link_type); http_details.has_value()) {
        return *http_details;
    }

    PacketDetailsService details_service {};
    if (const auto details = details_service.decode(bytes, packet); details.has_value()) {
        if (const auto generic_details = build_basic_protocol_details_text(*details); generic_details.has_value()) {
            return *generic_details;
        }
    }

    return std::string {kNoProtocolDetailsMessage};
}
std::optional<ReassemblyResult> CaptureSession::reassemble_flow_direction(const ReassemblyRequest& request) const {
    if (!has_loaded_state_) {
        return std::nullopt;
    }

    if (!has_source_capture()) {
        return std::nullopt;
    }

    if (!flow_packets(request.flow_index).has_value()) {
        return std::nullopt;
    }

    ReassemblyService service {};
    return service.reassemble_tcp_payload(*this, request);
}
std::optional<std::string> CaptureSession::derive_quic_service_hint_for_flow(const std::size_t flow_index) const {
    if (!has_source_capture()) {
        return std::nullopt;
    }

    const auto connections = list_connections(state_);
    if (flow_index >= connections.size()) {
        return std::nullopt;
    }

    constexpr std::size_t kOnDemandQuicHintPacketBudget = 4U;
    FlowHintService hint_service {analysis_settings_, true};

    const auto try_direction = [&](const auto& flow_key, const auto& packets) -> std::optional<std::string> {
        const auto packet_limit = std::min(kOnDemandQuicHintPacketBudget, packets.size());
        for (std::size_t index = 0U; index < packet_limit; ++index) {
            const auto& packet = packets[index];
            if (packet.is_ip_fragmented) {
                continue;
            }

            const auto packet_bytes = read_packet_data(packet);
            if (packet_bytes.empty()) {
                continue;
            }

            const auto hint = hint_service.detect(
                std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
                packet.data_link_type,
                flow_key);
            if (!hint.service_hint.empty()) {
                return hint.service_hint;
            }
        }

        return std::nullopt;
    };

    if (connections[flow_index].family == FlowAddressFamily::ipv4) {
        const auto& connection = *connections[flow_index].ipv4;
        if (connection.key.protocol != ProtocolId::udp) {
            return std::nullopt;
        }

        const auto try_flow = [&](const FlowV4& flow, const bool has_flow) -> std::optional<std::string> {
            if (!has_flow || flow.key.src_port == 443 || flow.key.dst_port != 443) {
                return std::nullopt;
            }
            return try_direction(flow.key, flow.packets);
        };

        if (const auto from_flow_a = try_flow(connection.flow_a, connection.has_flow_a); from_flow_a.has_value()) {
            return from_flow_a;
        }

        return try_flow(connection.flow_b, connection.has_flow_b);
    }

    const auto& connection = *connections[flow_index].ipv6;
    if (connection.key.protocol != ProtocolId::udp) {
        return std::nullopt;
    }

    const auto try_flow = [&](const FlowV6& flow, const bool has_flow) -> std::optional<std::string> {
        if (!has_flow || flow.key.src_port == 443 || flow.key.dst_port != 443) {
            return std::nullopt;
        }
        return try_direction(flow.key, flow.packets);
    };

    if (const auto from_flow_a = try_flow(connection.flow_a, connection.has_flow_a); from_flow_a.has_value()) {
        return from_flow_a;
    }

    return try_flow(connection.flow_b, connection.has_flow_b);
}

std::vector<FlowRow> CaptureSession::list_flows() const {
    const auto connections = list_connections(state_);
    std::vector<FlowRow> rows {};
    rows.reserve(connections.size());

    for (std::size_t index = 0; index < connections.size(); ++index) {
        rows.push_back(make_flow_row(index, connections[index], analysis_settings_));
    }

    return rows;
}

std::optional<FlowAnalysisResult> CaptureSession::get_flow_analysis(const std::size_t flow_index) const {
    const auto connections = list_connections(state_);
    if (flow_index >= connections.size()) {
        return std::nullopt;
    }

    FlowAnalysisService service {};
    auto result = connections[flow_index].family == FlowAddressFamily::ipv4
        ? service.analyze(*connections[flow_index].ipv4)
        : service.analyze(*connections[flow_index].ipv6);
    const auto hint = effective_protocol_hint(connections[flow_index], analysis_settings_);
    result.protocol_hint = hint == FlowProtocolHint::unknown ? std::string {} : std::string {flow_protocol_hint_text(hint)};
    return result;
}

std::vector<PacketRow> CaptureSession::list_flow_packets(const std::size_t flow_index) const {
    return list_flow_packets(flow_index, 0U, flow_packet_count(flow_index));
}

std::vector<PacketRow> CaptureSession::list_flow_packets(
    const std::size_t flow_index,
    const std::size_t offset,
    const std::size_t limit
) const {
    const auto connections = list_connections(state_);
    if (flow_index >= connections.size()) {
        return {};
    }

    if (connections[flow_index].family == FlowAddressFamily::ipv4) {
        return slice_connection_packets(*connections[flow_index].ipv4, offset, limit);
    }

    return slice_connection_packets(*connections[flow_index].ipv6, offset, limit);
}

std::size_t CaptureSession::flow_packet_count(const std::size_t flow_index) const noexcept {
    const auto connections = list_connections(state_);
    if (flow_index >= connections.size()) {
        return 0U;
    }

    if (connections[flow_index].family == FlowAddressFamily::ipv4) {
        return connection_packet_count(*connections[flow_index].ipv4);
    }

    return connection_packet_count(*connections[flow_index].ipv6);
}

std::vector<StreamItemRow> CaptureSession::list_flow_stream_items(const std::size_t flow_index) const {
    return list_flow_stream_items(flow_index, 0U, std::numeric_limits<std::size_t>::max());
}

std::vector<StreamItemRow> CaptureSession::list_flow_stream_items(
    const std::size_t flow_index,
    const std::size_t offset,
    const std::size_t limit
) const {
    if (limit == 0U || !has_source_capture()) {
        return {};
    }

    const auto connections = list_connections(state_);
    if (flow_index >= connections.size()) {
        return {};
    }

    const auto flow_protocol = protocol_id(connections[flow_index]);
    if (flow_protocol != ProtocolId::tcp && flow_protocol != ProtocolId::udp) {
        return {};
    }

    const auto maxTarget = std::numeric_limits<std::size_t>::max();
    const auto target = (offset > maxTarget - limit) ? maxTarget : offset + limit;

    std::vector<StreamItemRow> rows {};
    if (connections[flow_index].family == FlowAddressFamily::ipv4) {
        rows.reserve(std::min(target, connection_packet_count(*connections[flow_index].ipv4)));
    } else {
        rows.reserve(std::min(target, connection_packet_count(*connections[flow_index].ipv6)));
    }

    bool used_directional_tls_reassembly_a_to_b = false;
    bool used_directional_tls_reassembly_b_to_a = false;
    bool used_directional_http_reassembly_a_to_b = false;
    bool used_directional_http_reassembly_b_to_a = false;
    if (flow_protocol == ProtocolId::tcp) {
        used_directional_tls_reassembly_a_to_b = append_tls_stream_items_from_reassembly(
            rows,
            *this,
            flow_index,
            kDirectionAToB,
            Direction::a_to_b
        );
        used_directional_tls_reassembly_b_to_a = append_tls_stream_items_from_reassembly(
            rows,
            *this,
            flow_index,
            kDirectionBToA,
            Direction::b_to_a
        );
        if (!used_directional_tls_reassembly_a_to_b) {
            used_directional_http_reassembly_a_to_b = append_http_stream_items_from_reassembly(
                rows,
                *this,
                flow_index,
                kDirectionAToB,
                Direction::a_to_b
            );
        }
        if (!used_directional_tls_reassembly_b_to_a) {
            used_directional_http_reassembly_b_to_a = append_http_stream_items_from_reassembly(
                rows,
                *this,
                flow_index,
                kDirectionBToA,
                Direction::b_to_a
            );
        }
    }

    const bool skip_direction_a = used_directional_tls_reassembly_a_to_b || used_directional_http_reassembly_a_to_b;
    const bool skip_direction_b = used_directional_tls_reassembly_b_to_a || used_directional_http_reassembly_b_to_a;

    if (rows.size() < target) {
        if (connections[flow_index].family == FlowAddressFamily::ipv4) {
            append_connection_stream_items_bounded(
                rows,
                *this,
                *connections[flow_index].ipv4,
                flow_protocol,
                target,
                connection_packet_count(*connections[flow_index].ipv4),
                deep_protocol_details_enabled_,
                skip_direction_a,
                skip_direction_b
            );
        } else {
            append_connection_stream_items_bounded(
                rows,
                *this,
                *connections[flow_index].ipv6,
                flow_protocol,
                target,
                connection_packet_count(*connections[flow_index].ipv6),
                deep_protocol_details_enabled_,
                skip_direction_a,
                skip_direction_b
            );
        }
    }

    std::stable_sort(rows.begin(), rows.end(), [](const StreamItemRow& left, const StreamItemRow& right) {
        const auto left_packet_index = left.packet_indices.empty() ? std::numeric_limits<std::uint64_t>::max() : left.packet_indices.front();
        const auto right_packet_index = right.packet_indices.empty() ? std::numeric_limits<std::uint64_t>::max() : right.packet_indices.front();
        return left_packet_index < right_packet_index;
    });

    for (std::size_t index = 0; index < rows.size(); ++index) {
        rows[index].stream_item_index = static_cast<std::uint64_t>(index + 1U);
    }

    if (offset >= rows.size()) {
        return {};
    }

    const auto slice_end = std::min(rows.size(), target);
    return std::vector<StreamItemRow>(rows.begin() + static_cast<std::ptrdiff_t>(offset), rows.begin() + static_cast<std::ptrdiff_t>(slice_end));
}

std::vector<StreamItemRow> CaptureSession::list_flow_stream_items_for_packet_prefix(
    const std::size_t flow_index,
    const std::size_t max_packets_to_scan,
    const std::size_t limit
) const {
    if (limit == 0U || max_packets_to_scan == 0U || !has_source_capture()) {
        return {};
    }

    const auto total_packets = flow_packet_count(flow_index);
    if (total_packets <= max_packets_to_scan) {
        return list_flow_stream_items(flow_index, 0U, limit);
    }

    const auto connections = list_connections(state_);
    if (flow_index >= connections.size()) {
        return {};
    }

    const auto flow_protocol = protocol_id(connections[flow_index]);
    if (flow_protocol != ProtocolId::tcp && flow_protocol != ProtocolId::udp) {
        return {};
    }

    std::vector<StreamItemRow> rows {};
    rows.reserve(std::min(limit, max_packets_to_scan));

    if (connections[flow_index].family == FlowAddressFamily::ipv4) {
        append_connection_stream_items_bounded(
            rows,
            *this,
            *connections[flow_index].ipv4,
            flow_protocol,
            limit,
            max_packets_to_scan,
            deep_protocol_details_enabled_,
            false,
            false
        );
    } else {
        append_connection_stream_items_bounded(
            rows,
            *this,
            *connections[flow_index].ipv6,
            flow_protocol,
            limit,
            max_packets_to_scan,
            deep_protocol_details_enabled_,
            false,
            false
        );
    }

    std::stable_sort(rows.begin(), rows.end(), [](const StreamItemRow& left, const StreamItemRow& right) {
        const auto left_packet_index = left.packet_indices.empty() ? std::numeric_limits<std::uint64_t>::max() : left.packet_indices.front();
        const auto right_packet_index = right.packet_indices.empty() ? std::numeric_limits<std::uint64_t>::max() : right.packet_indices.front();
        return left_packet_index < right_packet_index;
    });

    for (std::size_t index = 0; index < rows.size(); ++index) {
        rows[index].stream_item_index = static_cast<std::uint64_t>(index + 1U);
    }

    return rows;
}
std::size_t CaptureSession::flow_stream_item_count(const std::size_t flow_index) const {
    return list_flow_stream_items(flow_index).size();
}

std::optional<std::vector<PacketRef>> CaptureSession::flow_packets(std::size_t flow_index) const {
    const auto connections = list_connections(state_);
    if (flow_index >= connections.size()) {
        return std::nullopt;
    }

    if (connections[flow_index].family == FlowAddressFamily::ipv4) {
        return collect_packets(*connections[flow_index].ipv4);
    }

    return collect_packets(*connections[flow_index].ipv6);
}

bool CaptureSession::export_flow_to_pcap(std::size_t flow_index, const std::filesystem::path& output_path) const {
    return export_flows_to_pcap({flow_index}, output_path);
}

bool CaptureSession::export_flows_to_pcap(const std::vector<std::size_t>& flow_indices, const std::filesystem::path& output_path) const {
    if (!has_source_capture() || flow_indices.empty()) {
        return false;
    }

    std::vector<PacketRef> packets {};
    for (const auto flow_index : flow_indices) {
        const auto flowPackets = flow_packets(flow_index);
        if (!flowPackets.has_value()) {
            return false;
        }

        packets.insert(packets.end(), flowPackets->begin(), flowPackets->end());
    }

    if (packets.empty()) {
        return false;
    }

    std::sort(packets.begin(), packets.end(), [](const PacketRef& left, const PacketRef& right) {
        return left.packet_index < right.packet_index;
    });
    packets.erase(std::unique(packets.begin(), packets.end(), [](const PacketRef& left, const PacketRef& right) {
        return left.packet_index == right.packet_index;
    }), packets.end());

    FlowExportService service {};
    return service.export_packets_to_pcap(output_path, packets, capture_path());
}

std::optional<PacketRef> CaptureSession::find_packet(std::uint64_t packet_index) const {
    for (const auto* connection : state_.ipv4_connections.list()) {
        const auto packet = find_packet_in_connection(*connection, packet_index);
        if (packet.has_value()) {
            return packet;
        }
    }

    for (const auto* connection : state_.ipv6_connections.list()) {
        const auto packet = find_packet_in_connection(*connection, packet_index);
        if (packet.has_value()) {
            return packet;
        }
    }

    return std::nullopt;
}

CaptureState& CaptureSession::state() noexcept {
    return state_;
}

const CaptureState& CaptureSession::state() const noexcept {
    return state_;
}

}  // namespace pfl









