#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace pfl {

class QuicInitialParser {
public:
    static constexpr std::size_t kMaxInitialPackets = 3U;
    static constexpr std::size_t kMaxCryptoBytes = 16U * 1024U;
    static constexpr std::size_t kMaxCryptoFrames = 64U;

    [[nodiscard]] bool is_client_initial_packet(std::span<const std::uint8_t> udp_payload) const noexcept;
    [[nodiscard]] std::optional<std::string> extract_client_initial_sni(std::span<const std::uint8_t> udp_payload) const;
    [[nodiscard]] std::optional<std::string> extract_client_initial_sni(std::span<const std::vector<std::uint8_t>> udp_payloads) const;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> extract_client_initial_crypto_prefix(
        std::span<const std::uint8_t> udp_payload
    ) const;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> extract_client_initial_crypto_prefix(
        std::span<const std::vector<std::uint8_t>> udp_payloads
    ) const;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> extract_crypto_prefix_from_payloads(
        std::span<const std::vector<std::uint8_t>> decrypted_initial_payloads
    ) const;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> decrypt_initial_plaintext(
        std::span<const std::uint8_t> udp_payload,
        bool use_server_initial_secret
    ) const;

    // Decrypted Initial payload helper used by bounded multi-packet assembly tests.
    [[nodiscard]] std::optional<std::string> extract_client_initial_sni_from_crypto_payloads(
        std::span<const std::vector<std::uint8_t>> decrypted_initial_payloads
    ) const;
};

}  // namespace pfl
