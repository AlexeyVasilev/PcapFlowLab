#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace pfl {

enum class DhcpOptionArea : std::uint8_t {
    main = 0,
    file,
    sname,
};

enum class DhcpOptionStatus : std::uint8_t {
    complete = 0,
    malformed,
};

enum class DhcpOptionSemanticKind : std::uint8_t {
    unknown = 0,
    subnet_mask,
    router,
    domain_name_server,
    host_name,
    domain_name,
    broadcast_address,
    requested_ip_address,
    lease_time,
    option_overload,
    message_type,
    server_identifier,
    parameter_request_list,
    message,
    maximum_message_size,
    renewal_time,
    rebinding_time,
    vendor_class_identifier,
    client_identifier,
    tftp_server_name,
    bootfile_name,
    end,
};

struct DhcpOption {
    DhcpOptionArea area {DhcpOptionArea::main};
    std::uint8_t code {0U};
    std::optional<std::uint8_t> declared_length {};
    std::uint8_t available_value_length {0U};
    DhcpOptionSemanticKind semantic_kind {DhcpOptionSemanticKind::unknown};
    DhcpOptionStatus status {DhcpOptionStatus::complete};
    std::vector<std::uint8_t> value {};
};

struct DhcpMessage {
    std::uint8_t op {0U};
    std::uint8_t htype {0U};
    std::uint8_t hlen {0U};
    std::uint8_t hops {0U};
    std::uint32_t xid {0U};
    std::uint16_t secs {0U};
    std::uint16_t flags {0U};
    std::uint32_t ciaddr {0U};
    std::uint32_t yiaddr {0U};
    std::uint32_t siaddr {0U};
    std::uint32_t giaddr {0U};
    std::array<std::uint8_t, 16> chaddr {};
    std::array<std::uint8_t, 64> sname {};
    std::array<std::uint8_t, 128> file {};
    std::uint32_t magic_cookie {0U};
    std::vector<DhcpOption> main_options {};
    std::vector<DhcpOption> file_options {};
    std::vector<DhcpOption> sname_options {};
    bool has_malformed_option {false};
    bool file_overloaded {false};
    bool sname_overloaded {false};
};

}  // namespace pfl
