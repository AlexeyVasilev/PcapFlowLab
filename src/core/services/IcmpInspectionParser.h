#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace pfl {

enum class IcmpInspectionStatus : std::uint8_t {
    complete = 0,
    truncated,
    malformed,
    not_enough_header,
};

enum class IcmpMessageKind : std::uint8_t {
    unknown = 0,
    echo_request,
    echo_reply,
    destination_unreachable,
    time_exceeded,
    redirect,
    parameter_problem,
};

struct IcmpQuotedDataInfo {
    std::uint32_t offset {0};
    std::uint32_t length {0};
};

struct IcmpEchoMessage {
    std::optional<std::uint16_t> identifier {};
    std::optional<std::uint16_t> sequence_number {};
    std::optional<std::uint32_t> payload_length {};
};

struct IcmpDestinationUnreachableMessage {
    std::optional<std::uint16_t> next_hop_mtu {};
    std::optional<IcmpQuotedDataInfo> quoted_data {};
};

struct IcmpTimeExceededMessage {
    std::optional<IcmpQuotedDataInfo> quoted_data {};
};

struct IcmpRedirectMessage {
    std::optional<std::uint32_t> gateway_address {};
    std::optional<IcmpQuotedDataInfo> quoted_data {};
};

struct IcmpParameterProblemMessage {
    std::optional<std::uint8_t> pointer {};
    std::optional<IcmpQuotedDataInfo> quoted_data {};
};

struct IcmpMessage {
    IcmpInspectionStatus status {IcmpInspectionStatus::not_enough_header};
    IcmpMessageKind kind {IcmpMessageKind::unknown};
    std::optional<std::uint8_t> type {};
    std::optional<std::uint8_t> code {};
    std::optional<std::uint16_t> checksum {};
    std::optional<IcmpEchoMessage> echo {};
    std::optional<IcmpDestinationUnreachableMessage> destination_unreachable {};
    std::optional<IcmpTimeExceededMessage> time_exceeded {};
    std::optional<IcmpRedirectMessage> redirect {};
    std::optional<IcmpParameterProblemMessage> parameter_problem {};
};

class IcmpInspectionParser {
public:
    [[nodiscard]] IcmpMessage inspect(
        std::span<const std::uint8_t> icmp_bytes,
        std::optional<std::size_t> declared_length = {}
    ) const;
};

[[nodiscard]] bool icmp_common_header_complete(const IcmpMessage& message) noexcept;

}  // namespace pfl
