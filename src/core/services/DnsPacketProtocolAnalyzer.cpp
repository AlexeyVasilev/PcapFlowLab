#include "core/services/DnsPacketProtocolAnalyzer.h"

#include <cctype>
#include <cstddef>
#include <optional>
#include <span>
#include <sstream>
#include <string>

#include "core/services/PacketPayloadService.h"
#include "core/io/LinkType.h"

namespace pfl {

namespace {

constexpr std::size_t kDnsHeaderSize = 12;

std::uint16_t read_be16(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                      static_cast<std::uint16_t>(bytes[offset + 1]));
}

bool is_plausible_label_char(const char value) noexcept {
    const auto byte = static_cast<unsigned char>(value);
    return std::isalnum(byte) != 0 || value == '-' || value == '_';
}

std::optional<std::string> parse_dns_name(std::span<const std::uint8_t> message,
                                          std::size_t& offset,
                                          std::size_t depth = 0) {
    if (depth > 8 || offset >= message.size()) {
        return std::nullopt;
    }

    std::string name {};
    bool first_label = true;

    while (offset < message.size()) {
        const auto label_length = static_cast<std::size_t>(message[offset]);
        if (label_length == 0U) {
            ++offset;
            return name.empty() ? std::optional<std::string> {std::string(".")} : std::optional<std::string> {name};
        }

        if ((label_length & 0xC0U) == 0xC0U) {
            if (offset + 1U >= message.size()) {
                return std::nullopt;
            }

            const auto pointer = static_cast<std::size_t>(((label_length & 0x3FU) << 8U) | message[offset + 1U]);
            offset += 2U;
            auto pointer_offset = pointer;
            const auto pointed_name = parse_dns_name(message, pointer_offset, depth + 1U);
            if (!pointed_name.has_value()) {
                return std::nullopt;
            }

            if (!first_label && *pointed_name != ".") {
                name.push_back('.');
            }
            if (*pointed_name != ".") {
                name += *pointed_name;
            }
            return name.empty() ? std::optional<std::string> {std::string(".")} : std::optional<std::string> {name};
        }

        ++offset;
        if (label_length > 63U || offset + label_length > message.size()) {
            return std::nullopt;
        }

        if (!first_label) {
            name.push_back('.');
        }
        first_label = false;

        for (std::size_t index = 0; index < label_length; ++index) {
            const auto character = static_cast<char>(message[offset + index]);
            if (!is_plausible_label_char(character)) {
                return std::nullopt;
            }
            name.push_back(character);
        }

        offset += label_length;
    }

    return std::nullopt;
}

std::optional<std::span<const std::uint8_t>> extract_dns_message(std::span<const std::uint8_t> payload) {
    if (payload.size() >= 2U) {
        const auto length_prefix = static_cast<std::size_t>(read_be16(payload, 0));
        if (length_prefix >= kDnsHeaderSize && payload.size() >= 2U + length_prefix) {
            return payload.subspan(2U, length_prefix);
        }
    }

    if (payload.size() >= kDnsHeaderSize) {
        return payload;
    }

    return std::nullopt;
}

std::string qtype_text(const std::uint16_t qtype) {
    switch (qtype) {
    case 1U:
        return "A (1)";
    case 28U:
        return "AAAA (28)";
    case 33U:
        return "SRV (33)";
    case 64U:
        return "SVCB (64)";
    case 65U:
        return "HTTPS (65)";
    default: {
        std::ostringstream builder {};
        builder << qtype;
        return builder.str();
    }
    }
}

}  // namespace

std::optional<std::string> DnsPacketProtocolAnalyzer::analyze(std::span<const std::uint8_t> packet_bytes) const {
    return analyze(packet_bytes, kLinkTypeEthernet);
}

std::optional<std::string> DnsPacketProtocolAnalyzer::analyze(std::span<const std::uint8_t> packet_bytes, const std::uint32_t data_link_type) const {
    PacketPayloadService payload_service {};
    const auto payload_bytes = payload_service.extract_transport_payload(packet_bytes, data_link_type);
    if (payload_bytes.empty()) {
        return std::nullopt;
    }

    const auto payload = std::span<const std::uint8_t>(payload_bytes.data(), payload_bytes.size());
    const auto message = extract_dns_message(payload);
    if (!message.has_value() || message->size() < kDnsHeaderSize) {
        return std::nullopt;
    }

    const auto flags = read_be16(*message, 2U);
    const auto qdcount = read_be16(*message, 4U);
    const auto ancount = read_be16(*message, 6U);
    if (qdcount == 0U || qdcount > 16U || ancount > 128U) {
        return std::nullopt;
    }

    std::size_t offset = kDnsHeaderSize;
    const auto qname = parse_dns_name(*message, offset);
    if (!qname.has_value() || offset + 4U > message->size()) {
        return std::nullopt;
    }

    const auto qtype = read_be16(*message, offset);

    std::ostringstream text {};
    text << "DNS\n"
         << "  Message Type: " << (((flags & 0x8000U) != 0U) ? "Response" : "Query") << "\n"
         << "  Transaction ID: 0x" << std::hex << std::uppercase << read_be16(*message, 0U) << std::dec << "\n"
         << "  Questions: " << qdcount << "\n"
         << "  Answers: " << ancount;

    if (*qname != ".") {
        text << "\n"
             << "  QName: " << *qname;
    }

    text << "\n"
         << "  QType: " << qtype_text(qtype);

    return text.str();
}

}  // namespace pfl



