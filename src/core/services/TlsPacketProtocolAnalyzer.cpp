#include "core/services/TlsPacketProtocolAnalyzer.h"

#include <cctype>
#include <cstddef>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>

#include "core/services/PacketPayloadService.h"
#include "core/io/LinkType.h"

namespace pfl {

namespace {

constexpr std::size_t kTlsRecordHeaderSize = 5;

std::uint16_t read_be16(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                      static_cast<std::uint16_t>(bytes[offset + 1]));
}

std::uint32_t read_be24(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 2]);
}

std::string_view bytes_as_text(std::span<const std::uint8_t> bytes) {
    return std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

bool is_plausible_service_name_char(const char value) noexcept {
    const auto byte = static_cast<unsigned char>(value);
    return std::isalnum(byte) != 0 || value == '.' || value == '-' || value == '_';
}

bool is_plausible_service_name(const std::string_view value) noexcept {
    if (value.empty()) {
        return false;
    }

    for (const auto character : value) {
        if (!is_plausible_service_name_char(character)) {
            return false;
        }
    }

    return true;
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

std::optional<std::string> extract_tls_sni(std::span<const std::uint8_t> payload) {
    if (!looks_like_tls_record(payload) || payload[0] != 0x16U) {
        return std::nullopt;
    }

    const auto record_length = static_cast<std::size_t>(read_be16(payload, 3));
    const auto record = payload.subspan(kTlsRecordHeaderSize, record_length);
    if (record.size() < 4U || record[0] != 0x01U) {
        return std::nullopt;
    }

    const auto handshake_length = static_cast<std::size_t>(read_be24(record, 1));
    if (record.size() < 4U + handshake_length) {
        return std::nullopt;
    }

    auto body = record.subspan(4, handshake_length);
    std::size_t offset = 0;
    if (body.size() < 34U) {
        return std::nullopt;
    }

    offset += 2;   // client version
    offset += 32;  // random

    const auto session_id_length = static_cast<std::size_t>(body[offset]);
    ++offset;
    if (body.size() < offset + session_id_length + 2U) {
        return std::nullopt;
    }
    offset += session_id_length;

    const auto cipher_suites_length = static_cast<std::size_t>(read_be16(body, offset));
    offset += 2;
    if (cipher_suites_length == 0U || body.size() < offset + cipher_suites_length + 1U) {
        return std::nullopt;
    }
    offset += cipher_suites_length;

    const auto compression_methods_length = static_cast<std::size_t>(body[offset]);
    ++offset;
    if (body.size() < offset + compression_methods_length + 2U) {
        return std::nullopt;
    }
    offset += compression_methods_length;

    const auto extensions_length = static_cast<std::size_t>(read_be16(body, offset));
    offset += 2;
    if (body.size() < offset + extensions_length) {
        return std::nullopt;
    }

    const auto extensions_end = offset + extensions_length;
    while (offset + 4U <= extensions_end) {
        const auto extension_type = read_be16(body, offset);
        const auto extension_length = static_cast<std::size_t>(read_be16(body, offset + 2U));
        offset += 4U;
        if (offset + extension_length > extensions_end) {
            return std::nullopt;
        }

        if (extension_type == 0x0000U) {
            auto server_name_extension = body.subspan(offset, extension_length);
            if (server_name_extension.size() < 2U) {
                return std::nullopt;
            }

            const auto server_name_list_length = static_cast<std::size_t>(read_be16(server_name_extension, 0));
            if (server_name_extension.size() < 2U + server_name_list_length) {
                return std::nullopt;
            }

            std::size_t name_offset = 2U;
            while (name_offset + 3U <= 2U + server_name_list_length) {
                const auto name_type = server_name_extension[name_offset];
                const auto name_length = static_cast<std::size_t>(read_be16(server_name_extension, name_offset + 1U));
                name_offset += 3U;
                if (name_offset + name_length > 2U + server_name_list_length) {
                    return std::nullopt;
                }

                if (name_type == 0U) {
                    const auto server_name = bytes_as_text(server_name_extension.subspan(name_offset, name_length));
                    if (is_plausible_service_name(server_name)) {
                        return std::string(server_name);
                    }
                    return std::nullopt;
                }

                name_offset += name_length;
            }
        }

        offset += extension_length;
    }

    return std::nullopt;
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
        if (record.size() >= 4U) {
            const auto handshake_type = record[0];
            const auto handshake_length = static_cast<std::size_t>(read_be24(record, 1));
            text << "\n"
                 << "  Handshake Type: " << tls_handshake_type_text(handshake_type) << "\n"
                 << "  Handshake Length: " << handshake_length;

            const auto sni = extract_tls_sni(payload);
            if (sni.has_value()) {
                text << "\n"
                     << "  SNI: " << *sni;
            }
        }
    }

    return text.str();
}

}  // namespace pfl


