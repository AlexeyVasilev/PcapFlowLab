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

std::optional<std::uint32_t> narrow_u32(const std::size_t value) noexcept {
    if (value > 0xFFFFFFFFU) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(value);
}

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

struct DnsMessageSlice {
    std::span<const std::uint8_t> bytes {};
    std::size_t payload_offset {0U};
    bool tcp_length_prefixed {false};
};

std::optional<DnsMessageSlice> extract_dns_message(std::span<const std::uint8_t> payload) {
    if (payload.size() >= 2U) {
        const auto length_prefix = static_cast<std::size_t>(read_be16(payload, 0));
        if (length_prefix >= kDnsHeaderSize && payload.size() >= 2U + length_prefix) {
            return DnsMessageSlice {
                .bytes = payload.subspan(2U, length_prefix),
                .payload_offset = 2U,
                .tcp_length_prefixed = true,
            };
        }
    }

    if (payload.size() >= kDnsHeaderSize) {
        return DnsMessageSlice {
            .bytes = payload,
            .payload_offset = 0U,
            .tcp_length_prefixed = false,
        };
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

std::optional<DnsPacketMessageView> DnsPacketProtocolAnalyzer::inspect_message(
    std::span<const std::uint8_t> packet_bytes
) const {
    return inspect_message(packet_bytes, kLinkTypeEthernet);
}

std::optional<DnsPacketMessageView> DnsPacketProtocolAnalyzer::inspect_message(
    std::span<const std::uint8_t> packet_bytes,
    const std::uint32_t data_link_type
) const {
    PacketPayloadService payload_service {};
    const auto payload = payload_service.extract_transport_payload_view(packet_bytes, data_link_type);
    if (!payload.found || payload.payload.empty()) {
        return std::nullopt;
    }

    const auto message = extract_dns_message(payload.payload);
    if (!message.has_value() || message->bytes.size() < kDnsHeaderSize) {
        return std::nullopt;
    }

    const auto flags = read_be16(message->bytes, 2U);
    const auto qdcount = read_be16(message->bytes, 4U);
    const auto ancount = read_be16(message->bytes, 6U);
    if (qdcount == 0U || qdcount > 16U || ancount > 128U) {
        return std::nullopt;
    }

    std::size_t offset = kDnsHeaderSize;
    const auto qname = parse_dns_name(message->bytes, offset);
    if (!qname.has_value() || offset + 4U > message->bytes.size()) {
        return std::nullopt;
    }

    const auto qtype = read_be16(message->bytes, offset);

    const auto message_offset = narrow_u32(payload.offset + message->payload_offset);
    const auto declared_length = narrow_u32(message->bytes.size());
    if (!message_offset.has_value() || !declared_length.has_value()) {
        return std::nullopt;
    }

    return DnsPacketMessageView {
        .message_range = PacketByteRange {
            .offset = *message_offset,
            .declared_length = declared_length,
            .captured_length = *declared_length,
            .truncated = false,
        },
        .tcp_length_prefixed = message->tcp_length_prefixed,
        .is_response = (flags & 0x8000U) != 0U,
        .transaction_id = read_be16(message->bytes, 0U),
        .question_count = qdcount,
        .answer_count = ancount,
        .query_type = qtype,
        .response_code = static_cast<std::uint8_t>(flags & 0x000FU),
        .query_name = *qname,
    };
}

std::optional<std::string> DnsPacketProtocolAnalyzer::analyze(
    std::span<const std::uint8_t> packet_bytes,
    const std::uint32_t data_link_type
) const {
    const auto message = inspect_message(packet_bytes, data_link_type);
    if (!message.has_value()) {
        return std::nullopt;
    }

    std::ostringstream text {};
    text << "DNS\n"
         << "  Message Type: " << (message->is_response ? "Response" : "Query") << "\n"
         << "  Transaction ID: 0x" << std::hex << std::uppercase << message->transaction_id << std::dec << "\n"
         << "  Questions: " << message->question_count << "\n"
         << "  Answers: " << message->answer_count;

    if (message->query_name != ".") {
        text << "\n"
             << "  QName: " << message->query_name;
    }

    text << "\n"
         << "  QType: " << qtype_text(message->query_type);

    return text.str();
}

}  // namespace pfl



