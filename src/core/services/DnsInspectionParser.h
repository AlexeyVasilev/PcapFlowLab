#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace pfl {

enum class DnsInspectionStatus : std::uint8_t {
    complete = 0,
    truncated,
    malformed,
    not_enough_header,
};

enum class DnsRdataKind : std::uint8_t {
    none = 0,
    a,
    aaaa,
    cname,
    ptr,
    srv,
    txt,
    ns,
    mx,
    opaque,
};

enum class DnsRdataParseStatus : std::uint8_t {
    not_present = 0,
    parsed,
    not_supported,
    malformed,
    truncated,
};

struct DnsTxtChunk {
    std::vector<std::uint8_t> bytes {};
};

struct DnsRdata {
    DnsRdataKind kind {DnsRdataKind::none};
    DnsRdataParseStatus parse_status {DnsRdataParseStatus::not_present};
    std::array<std::uint8_t, 16> address_bytes {};
    std::uint8_t address_size {0};
    std::string name {};
    std::uint16_t srv_priority {0};
    std::uint16_t srv_weight {0};
    std::uint16_t srv_port {0};
    std::string srv_target {};
    std::vector<DnsTxtChunk> txt_chunks {};
    std::uint16_t mx_preference {0};
    std::string mx_exchange {};
    std::vector<std::uint8_t> opaque_bytes {};
};

struct DnsQuestion {
    std::string name {};
    std::uint16_t type {0};
    std::uint16_t raw_class {0};
};

struct DnsResourceRecord {
    std::string name {};
    std::uint16_t type {0};
    std::uint16_t raw_class {0};
    std::uint32_t ttl {0};
    std::uint16_t rdlength {0};
    DnsRdata rdata {};
};

struct DnsMessage {
    DnsInspectionStatus status {DnsInspectionStatus::not_enough_header};
    std::uint16_t transaction_id {0};
    std::uint16_t raw_flags {0};
    bool is_response {false};
    std::uint8_t opcode {0};
    bool authoritative_answer {false};
    bool truncated {false};
    bool recursion_desired {false};
    bool recursion_available {false};
    std::uint8_t response_code {0};
    std::uint16_t declared_question_count {0};
    std::uint16_t declared_answer_count {0};
    std::uint16_t declared_authority_count {0};
    std::uint16_t declared_additional_count {0};
    std::vector<DnsQuestion> questions {};
    std::vector<DnsResourceRecord> answers {};
    std::vector<DnsResourceRecord> authorities {};
    std::vector<DnsResourceRecord> additionals {};
};

class DnsInspectionParser {
public:
    [[nodiscard]] DnsMessage inspect(std::span<const std::uint8_t> dns_bytes) const;
};

}  // namespace pfl
