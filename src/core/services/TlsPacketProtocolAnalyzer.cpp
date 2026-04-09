#include "core/services/TlsPacketProtocolAnalyzer.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <iomanip>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "core/services/PacketPayloadService.h"
#include "core/services/TlsHandshakeDetails.h"
#include "core/io/LinkType.h"

namespace pfl {

namespace {

constexpr std::size_t kTlsRecordHeaderSize = 5;

std::uint16_t read_be16(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                      static_cast<std::uint16_t>(bytes[offset + 1]));
}

bool looks_like_tls_record(std::span<const std::uint8_t> payload) {
    if (payload.size() < kTlsRecordHeaderSize) {
        return false;
    }

    const auto content_type = payload[0];
    if (content_type < 20U || content_type > 23U) {
        return false;
    }

    if (payload[1] != 0x03U || payload[2] > 0x04U) {
        return false;
    }

    const auto record_length = static_cast<std::size_t>(read_be16(payload, 3));
    return record_length > 0U && record_length <= (payload.size() - kTlsRecordHeaderSize);
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

std::string tls_version_text(const std::uint16_t version) {
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

}  // namespace

std::optional<std::string> TlsPacketProtocolAnalyzer::analyze(std::span<const std::uint8_t> packet_bytes) const {
    return analyze(packet_bytes, kLinkTypeEthernet);
}

std::optional<std::string> TlsPacketProtocolAnalyzer::analyze(std::span<const std::uint8_t> packet_bytes, const std::uint32_t data_link_type) const {
    PacketPayloadService payload_service {};
    const auto payload_bytes = payload_service.extract_transport_payload(packet_bytes, data_link_type);
    if (payload_bytes.empty()) {
        return std::nullopt;
    }

    const auto payload = std::span<const std::uint8_t>(payload_bytes.data(), payload_bytes.size());
    if (!looks_like_tls_record(payload)) {
        return std::nullopt;
    }

    const auto content_type = payload[0];
    const auto version = read_be16(payload, 1);
    const auto record_length = static_cast<std::size_t>(read_be16(payload, 3));

    std::ostringstream text {};
    text << "TLS\n"
         << "  Record Type: " << tls_record_type_text(content_type) << "\n"
         << "  Record Version: " << tls_version_text(version) << "\n"
         << "  Record Length: " << record_length;

    if (content_type == 0x16U) {
        const auto record = payload.subspan(kTlsRecordHeaderSize, record_length);
        const auto handshake_details = parse_tls_handshake_details(record);
        if (handshake_details.has_value()) {
            text << "\n"
                 << "  Handshake Type: " << handshake_details->handshake_type_text << "\n"
                 << "  Handshake Length: " << handshake_details->handshake_length;

            if (!handshake_details->details_text.empty()) {
                text << "\n" << handshake_details->details_text;
            }
        }
    }

    return text.str();
}

}  // namespace pfl


