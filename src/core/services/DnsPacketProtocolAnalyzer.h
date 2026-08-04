#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>

#include "core/domain/PacketDetails.h"

namespace pfl {

struct DnsPacketMessageView {
    PacketByteRange message_range {};
    bool tcp_length_prefixed {false};
    bool is_response {false};
    std::uint16_t transaction_id {0};
    std::uint16_t question_count {0};
    std::uint16_t answer_count {0};
    std::uint16_t query_type {0};
    std::optional<std::uint8_t> response_code {};
    std::string query_name {};
};

class DnsPacketProtocolAnalyzer {
public:
    [[nodiscard]] std::optional<DnsPacketMessageView> inspect_message(std::span<const std::uint8_t> packet_bytes) const;
    [[nodiscard]] std::optional<DnsPacketMessageView> inspect_message(
        std::span<const std::uint8_t> packet_bytes,
        std::uint32_t data_link_type
    ) const;
    [[nodiscard]] std::optional<std::string> analyze(std::span<const std::uint8_t> packet_bytes) const;
    [[nodiscard]] std::optional<std::string> analyze(std::span<const std::uint8_t> packet_bytes, std::uint32_t data_link_type) const;
};

}  // namespace pfl

