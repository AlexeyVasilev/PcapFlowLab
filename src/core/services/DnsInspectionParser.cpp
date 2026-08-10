#include "core/services/DnsInspectionParser.h"

#include <algorithm>
#include <array>
#include <optional>
#include <type_traits>
#include <utility>

namespace pfl {

namespace {

constexpr std::size_t kDnsHeaderSize = 12U;
constexpr std::size_t kMaxQuestions = 128U;
constexpr std::size_t kMaxRecordsPerSection = 256U;
constexpr std::size_t kMaxTotalRecords = 512U;
constexpr std::size_t kMaxPointerHops = 32U;
constexpr std::size_t kMaxNameLength = 255U;
constexpr std::size_t kMaxLabelCount = 128U;
constexpr std::size_t kMaxTxtChunks = 128U;

std::uint16_t read_be16(std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[offset]) << 8U) |
        static_cast<std::uint16_t>(bytes[offset + 1U]));
}

std::uint32_t read_be32(std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
        (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
        (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
        static_cast<std::uint32_t>(bytes[offset + 3U]);
}

struct DecodedDnsName {
    bool success {false};
    bool truncated {false};
    std::size_t consumed_bytes {0U};
    std::string name {};
};

DecodedDnsName decode_dns_name(
    std::span<const std::uint8_t> message_bytes,
    const std::size_t start_offset,
    const std::size_t source_limit
) {
    if (start_offset >= message_bytes.size() || start_offset >= source_limit) {
        return {};
    }

    std::size_t current = start_offset;
    std::size_t consumed = 0U;
    std::size_t pointer_hops = 0U;
    std::array<std::size_t, kMaxPointerHops> pointer_targets {};
    std::size_t pointer_target_count = 0U;
    std::size_t label_count = 0U;
    std::string name {};
    bool jumped = false;
    bool first_label = true;

    while (true) {
        if (current >= message_bytes.size()) {
            return DecodedDnsName {.truncated = true};
        }

        const auto available_limit = jumped ? message_bytes.size() : source_limit;
        if (current >= available_limit) {
            return DecodedDnsName {.truncated = true};
        }

        const auto length_or_tag = static_cast<std::size_t>(message_bytes[current]);
        if (length_or_tag == 0U) {
            if (!jumped) {
                ++consumed;
            }
            return DecodedDnsName {
                .success = true,
                .truncated = false,
                .consumed_bytes = consumed,
                .name = name.empty() ? std::string(".") : name,
            };
        }

        if ((length_or_tag & 0xC0U) == 0xC0U) {
            if (current + 1U >= available_limit || current + 1U >= message_bytes.size()) {
                return DecodedDnsName {.truncated = true};
            }

            if (pointer_hops >= kMaxPointerHops) {
                return {};
            }
            ++pointer_hops;

            const auto pointer_target = static_cast<std::size_t>(
                ((length_or_tag & 0x3FU) << 8U) | message_bytes[current + 1U]);
            if (pointer_target >= message_bytes.size()) {
                return {};
            }
            for (std::size_t index = 0U; index < pointer_target_count; ++index) {
                if (pointer_targets[index] == pointer_target) {
                    return {};
                }
            }
            pointer_targets[pointer_target_count] = pointer_target;
            ++pointer_target_count;

            if (!jumped) {
                consumed += 2U;
            }
            current = pointer_target;
            jumped = true;
            continue;
        }

        if ((length_or_tag & 0xC0U) != 0U) {
            return {};
        }

        const auto label_length = length_or_tag;
        if (label_length > 63U) {
            return {};
        }

        const auto label_start = current + 1U;
        const auto label_end = label_start + label_length;
        if (label_end > available_limit || label_end > message_bytes.size()) {
            return DecodedDnsName {.truncated = true};
        }

        if (label_count >= kMaxLabelCount) {
            return {};
        }
        ++label_count;

        if (!first_label) {
            name.push_back('.');
        }
        first_label = false;
        name.append(
            reinterpret_cast<const char*>(message_bytes.data() + static_cast<std::ptrdiff_t>(label_start)),
            label_length);
        if (name.size() > kMaxNameLength) {
            return {};
        }

        if (!jumped) {
            consumed += 1U + label_length;
        }
        current = label_end;
    }
}

struct ParseSectionResult {
    bool success {true};
    bool truncated {false};
    std::size_t next_offset {0U};
};

void degrade_message_status(DnsMessage& message, const DnsInspectionStatus candidate) noexcept {
    if (message.status == DnsInspectionStatus::malformed) {
        return;
    }
    if (candidate == DnsInspectionStatus::malformed) {
        message.status = candidate;
        return;
    }
    if (message.status == DnsInspectionStatus::complete) {
        message.status = candidate;
    }
}

std::optional<DnsQuestion> parse_question(
    std::span<const std::uint8_t> message_bytes,
    std::size_t& offset,
    DnsInspectionStatus& status
) {
    const auto name = decode_dns_name(message_bytes, offset, message_bytes.size());
    if (!name.success) {
        status = name.truncated ? DnsInspectionStatus::truncated : DnsInspectionStatus::malformed;
        return std::nullopt;
    }

    offset += name.consumed_bytes;
    if (offset + 4U > message_bytes.size()) {
        status = DnsInspectionStatus::truncated;
        return std::nullopt;
    }

    DnsQuestion question {
        .name = std::move(name.name),
        .type = read_be16(message_bytes, offset),
        .raw_class = read_be16(message_bytes, offset + 2U),
    };
    offset += 4U;
    return question;
}

DnsRdata parse_rdata(
    std::span<const std::uint8_t> message_bytes,
    const std::size_t rdata_offset,
    const std::uint16_t type,
    const std::uint16_t rdlength
) {
    const auto rdata_end = rdata_offset + static_cast<std::size_t>(rdlength);
    if (rdata_end > message_bytes.size()) {
        return DnsRdata {
            .kind = DnsRdataKind::opaque,
            .parse_status = DnsRdataParseStatus::truncated,
        };
    }

    const auto rdata_bytes = message_bytes.subspan(rdata_offset, rdlength);

    switch (type) {
    case 1U:
        if (rdlength != 4U) {
            return DnsRdata {.kind = DnsRdataKind::a, .parse_status = DnsRdataParseStatus::malformed};
        }
        return DnsRdata {
            .kind = DnsRdataKind::a,
            .parse_status = DnsRdataParseStatus::parsed,
            .address_bytes = {rdata_bytes[0], rdata_bytes[1], rdata_bytes[2], rdata_bytes[3]},
            .address_size = 4U,
        };
    case 28U: {
        if (rdlength != 16U) {
            return DnsRdata {.kind = DnsRdataKind::aaaa, .parse_status = DnsRdataParseStatus::malformed};
        }
        DnsRdata rdata {.kind = DnsRdataKind::aaaa, .parse_status = DnsRdataParseStatus::parsed, .address_size = 16U};
        std::copy(rdata_bytes.begin(), rdata_bytes.end(), rdata.address_bytes.begin());
        return rdata;
    }
    case 5U:
    case 12U:
    case 2U: {
        const auto decoded = decode_dns_name(message_bytes, rdata_offset, rdata_end);
        const auto kind = type == 5U ? DnsRdataKind::cname : type == 12U ? DnsRdataKind::ptr : DnsRdataKind::ns;
        if (!decoded.success) {
            return DnsRdata {
                .kind = kind,
                .parse_status = decoded.truncated ? DnsRdataParseStatus::truncated : DnsRdataParseStatus::malformed,
            };
        }
        return DnsRdata {
            .kind = kind,
            .parse_status = DnsRdataParseStatus::parsed,
            .name = std::move(decoded.name),
        };
    }
    case 33U: {
        if (rdlength < 6U) {
            return DnsRdata {.kind = DnsRdataKind::srv, .parse_status = DnsRdataParseStatus::truncated};
        }
        const auto target = decode_dns_name(message_bytes, rdata_offset + 6U, rdata_end);
        if (!target.success) {
            return DnsRdata {
                .kind = DnsRdataKind::srv,
                .parse_status = target.truncated ? DnsRdataParseStatus::truncated : DnsRdataParseStatus::malformed,
            };
        }
        return DnsRdata {
            .kind = DnsRdataKind::srv,
            .parse_status = DnsRdataParseStatus::parsed,
            .srv_priority = read_be16(message_bytes, rdata_offset),
            .srv_weight = read_be16(message_bytes, rdata_offset + 2U),
            .srv_port = read_be16(message_bytes, rdata_offset + 4U),
            .srv_target = std::move(target.name),
        };
    }
    case 16U: {
        DnsRdata rdata {.kind = DnsRdataKind::txt, .parse_status = DnsRdataParseStatus::parsed};
        std::size_t local_offset = 0U;
        while (local_offset < rdata_bytes.size()) {
            if (rdata.txt_chunks.size() >= kMaxTxtChunks) {
                rdata.parse_status = DnsRdataParseStatus::malformed;
                return rdata;
            }

            const auto chunk_length = static_cast<std::size_t>(rdata_bytes[local_offset]);
            ++local_offset;
            if (local_offset + chunk_length > rdata_bytes.size()) {
                rdata.parse_status = DnsRdataParseStatus::truncated;
                return rdata;
            }

            DnsTxtChunk chunk {};
            chunk.bytes.assign(
                rdata_bytes.begin() + static_cast<std::ptrdiff_t>(local_offset),
                rdata_bytes.begin() + static_cast<std::ptrdiff_t>(local_offset + chunk_length));
            rdata.txt_chunks.push_back(std::move(chunk));
            local_offset += chunk_length;
        }
        return rdata;
    }
    case 15U: {
        if (rdlength < 3U) {
            return DnsRdata {.kind = DnsRdataKind::mx, .parse_status = DnsRdataParseStatus::truncated};
        }
        const auto exchange = decode_dns_name(message_bytes, rdata_offset + 2U, rdata_end);
        if (!exchange.success) {
            return DnsRdata {
                .kind = DnsRdataKind::mx,
                .parse_status = exchange.truncated ? DnsRdataParseStatus::truncated : DnsRdataParseStatus::malformed,
            };
        }
        return DnsRdata {
            .kind = DnsRdataKind::mx,
            .parse_status = DnsRdataParseStatus::parsed,
            .mx_preference = read_be16(message_bytes, rdata_offset),
            .mx_exchange = std::move(exchange.name),
        };
    }
    case 64U:
    case 65U:
    default: {
        DnsRdata rdata {
            .kind = DnsRdataKind::opaque,
            .parse_status = (type == 64U || type == 65U)
                ? DnsRdataParseStatus::not_supported
                : DnsRdataParseStatus::not_supported,
        };
        rdata.opaque_bytes.assign(rdata_bytes.begin(), rdata_bytes.end());
        return rdata;
    }
    }
}

std::optional<DnsResourceRecord> parse_resource_record(
    std::span<const std::uint8_t> message_bytes,
    std::size_t& offset,
    DnsInspectionStatus& status
) {
    const auto name = decode_dns_name(message_bytes, offset, message_bytes.size());
    if (!name.success) {
        status = name.truncated ? DnsInspectionStatus::truncated : DnsInspectionStatus::malformed;
        return std::nullopt;
    }

    offset += name.consumed_bytes;
    if (offset + 10U > message_bytes.size()) {
        status = DnsInspectionStatus::truncated;
        return std::nullopt;
    }

    DnsResourceRecord record {};
    record.name = std::move(name.name);
    record.type = read_be16(message_bytes, offset);
    record.raw_class = read_be16(message_bytes, offset + 2U);
    record.ttl = read_be32(message_bytes, offset + 4U);
    record.rdlength = read_be16(message_bytes, offset + 8U);
    offset += 10U;

    record.rdata = parse_rdata(message_bytes, offset, record.type, record.rdlength);
    if (record.rdata.parse_status == DnsRdataParseStatus::truncated) {
        status = DnsInspectionStatus::truncated;
    } else if (record.rdata.parse_status == DnsRdataParseStatus::malformed) {
        status = DnsInspectionStatus::malformed;
    }

    if (offset + static_cast<std::size_t>(record.rdlength) > message_bytes.size()) {
        offset = message_bytes.size();
        return std::optional<DnsResourceRecord> {std::move(record)};
    }

    offset += static_cast<std::size_t>(record.rdlength);
    return std::optional<DnsResourceRecord> {std::move(record)};
}

template <typename T>
ParseSectionResult parse_section(
    std::span<const std::uint8_t> message_bytes,
    std::size_t start_offset,
    const std::uint16_t declared_count,
    const std::size_t max_count,
    std::vector<T>& output,
    DnsMessage& message,
    const bool records
) {
    std::size_t offset = start_offset;
    if (declared_count > max_count) {
        degrade_message_status(message, DnsInspectionStatus::malformed);
        return ParseSectionResult {.success = false, .truncated = false, .next_offset = offset};
    }

    for (std::size_t index = 0U; index < declared_count; ++index) {
        DnsInspectionStatus item_status = DnsInspectionStatus::complete;
        if constexpr (std::is_same_v<T, DnsQuestion>) {
            const auto parsed = parse_question(message_bytes, offset, item_status);
            if (!parsed.has_value()) {
                degrade_message_status(message, item_status);
                return ParseSectionResult {.success = false, .truncated = item_status == DnsInspectionStatus::truncated, .next_offset = offset};
            }
            output.push_back(*parsed);
        } else {
            const auto parsed = parse_resource_record(message_bytes, offset, item_status);
            if (!parsed.has_value()) {
                degrade_message_status(message, item_status);
                return ParseSectionResult {.success = false, .truncated = item_status == DnsInspectionStatus::truncated, .next_offset = offset};
            }
            output.push_back(*parsed);
            if (item_status != DnsInspectionStatus::complete) {
                degrade_message_status(message, item_status);
                return ParseSectionResult {.success = false, .truncated = item_status == DnsInspectionStatus::truncated, .next_offset = offset};
            }
        }
    }

    static_cast<void>(records);
    return ParseSectionResult {.success = true, .truncated = false, .next_offset = offset};
}

}  // namespace

DnsMessage DnsInspectionParser::inspect(std::span<const std::uint8_t> dns_bytes) const {
    DnsMessage message {};
    if (dns_bytes.size() < kDnsHeaderSize) {
        message.status = DnsInspectionStatus::not_enough_header;
        return message;
    }

    message.status = DnsInspectionStatus::complete;
    message.transaction_id = read_be16(dns_bytes, 0U);
    message.raw_flags = read_be16(dns_bytes, 2U);
    message.is_response = (message.raw_flags & 0x8000U) != 0U;
    message.opcode = static_cast<std::uint8_t>((message.raw_flags >> 11U) & 0x0FU);
    message.authoritative_answer = (message.raw_flags & 0x0400U) != 0U;
    message.truncated = (message.raw_flags & 0x0200U) != 0U;
    message.recursion_desired = (message.raw_flags & 0x0100U) != 0U;
    message.recursion_available = (message.raw_flags & 0x0080U) != 0U;
    message.response_code = static_cast<std::uint8_t>(message.raw_flags & 0x000FU);
    message.declared_question_count = read_be16(dns_bytes, 4U);
    message.declared_answer_count = read_be16(dns_bytes, 6U);
    message.declared_authority_count = read_be16(dns_bytes, 8U);
    message.declared_additional_count = read_be16(dns_bytes, 10U);

    const auto total_records =
        static_cast<std::size_t>(message.declared_answer_count) +
        static_cast<std::size_t>(message.declared_authority_count) +
        static_cast<std::size_t>(message.declared_additional_count);
    if (message.declared_question_count > kMaxQuestions || total_records > kMaxTotalRecords) {
        message.status = DnsInspectionStatus::malformed;
        return message;
    }

    std::size_t offset = kDnsHeaderSize;
    const auto questions = parse_section(
        dns_bytes,
        offset,
        message.declared_question_count,
        kMaxQuestions,
        message.questions,
        message,
        false);
    offset = questions.next_offset;
    if (!questions.success) {
        return message;
    }

    const auto answers = parse_section(
        dns_bytes,
        offset,
        message.declared_answer_count,
        kMaxRecordsPerSection,
        message.answers,
        message,
        true);
    offset = answers.next_offset;
    if (!answers.success) {
        return message;
    }

    const auto authorities = parse_section(
        dns_bytes,
        offset,
        message.declared_authority_count,
        kMaxRecordsPerSection,
        message.authorities,
        message,
        true);
    offset = authorities.next_offset;
    if (!authorities.success) {
        return message;
    }

    const auto additionals = parse_section(
        dns_bytes,
        offset,
        message.declared_additional_count,
        kMaxRecordsPerSection,
        message.additionals,
        message,
        true);
    if (!additionals.success) {
        return message;
    }

    return message;
}

}  // namespace pfl
