#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace pfl {

struct TlsHandshakeDetails {
    std::uint8_t handshake_type {0U};
    std::size_t handshake_length {0U};
    std::string handshake_type_text {};
    std::string details_text {};
};

[[nodiscard]] std::optional<TlsHandshakeDetails> parse_tls_handshake_details(
    std::span<const std::uint8_t> handshake_bytes
);

}  // namespace pfl