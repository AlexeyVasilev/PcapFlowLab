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

