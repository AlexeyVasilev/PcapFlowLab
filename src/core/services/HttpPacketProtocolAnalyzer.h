#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace pfl {

enum class HttpPacketMessageType : std::uint8_t {
    unknown,
    request,
    response,
};

struct HttpPacketMessageView {
    HttpPacketMessageType message_type {HttpPacketMessageType::unknown};
    std::string method {};
    std::string path {};
    std::string version {};
    std::string host {};
    std::string status_code {};
    std::string reason {};
};

class HttpPacketProtocolAnalyzer {
public:
    [[nodiscard]] std::optional<HttpPacketMessageView> inspect_message(std::span<const std::uint8_t> packet_bytes) const;
    [[nodiscard]] std::optional<HttpPacketMessageView> inspect_message(
        std::span<const std::uint8_t> packet_bytes,
        std::uint32_t data_link_type
    ) const;
    [[nodiscard]] std::optional<std::string> analyze(std::span<const std::uint8_t> packet_bytes) const;
    [[nodiscard]] std::optional<std::string> analyze(std::span<const std::uint8_t> packet_bytes, std::uint32_t data_link_type) const;
};

}  // namespace pfl

