#include "core/services/QuicInitialParser.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif

namespace pfl {

namespace {

constexpr std::uint32_t kQuicVersion1 = 0x00000001U;
constexpr std::uint32_t kQuicVersionV2 = 0x6B3343CFU;
constexpr std::uint32_t kQuicVersionDraft29 = 0xFF00001DU;
constexpr std::size_t kQuicSampleSize = 16U;
constexpr std::size_t kQuicTagSize = 16U;
constexpr std::size_t kQuicInitialSecretSize = 32U;
constexpr std::size_t kQuicAes128KeySize = 16U;
constexpr std::size_t kQuicIvSize = 12U;

constexpr std::array<std::uint8_t, 20> kQuicInitialSaltV1 {
    0x38U, 0x76U, 0x2CU, 0xF7U, 0xF5U, 0x59U, 0x34U, 0xB3U, 0x4DU, 0x17U,
    0x9AU, 0xE6U, 0xA4U, 0xC8U, 0x0CU, 0xADU, 0xCCU, 0xBBU, 0x7FU, 0x0AU,
};

// QUIC v2 Initial salt (RFC 9369).
constexpr std::array<std::uint8_t, 20> kQuicInitialSaltV2 {
    0x0DU, 0xEDU, 0xE3U, 0xDEU, 0xF7U, 0x00U, 0xA6U, 0xDBU, 0x81U, 0x93U,
    0x81U, 0xBEU, 0x6EU, 0x26U, 0x9DU, 0xCBU, 0xF9U, 0xBDU, 0x2EU, 0xD9U,
};

// QUIC draft-29 Initial salt (version 0xff00001d).
constexpr std::array<std::uint8_t, 20> kQuicInitialSaltDraft29 {
    0xAFU, 0xBFU, 0xECU, 0x28U, 0x99U, 0x93U, 0xD2U, 0x4CU, 0x9EU, 0x97U,
    0x86U, 0xF1U, 0x9CU, 0x61U, 0x11U, 0xE0U, 0x43U, 0x90U, 0xA8U, 0x99U,
};

struct QuicInitialVersionParams {
    std::span<const std::uint8_t> initial_salt {};
    std::string_view key_label {};
    std::string_view iv_label {};
    std::string_view hp_label {};
    std::uint8_t initial_packet_type_bits {0U};
};

std::optional<QuicInitialVersionParams> quic_initial_version_params(const std::uint32_t version) {
    switch (version) {
    case kQuicVersion1:
        return QuicInitialVersionParams {
            .initial_salt = std::span<const std::uint8_t>(kQuicInitialSaltV1.data(), kQuicInitialSaltV1.size()),
            .key_label = "quic key",
            .iv_label = "quic iv",
            .hp_label = "quic hp",
            .initial_packet_type_bits = 0U,
        };
    case kQuicVersionV2:
        return QuicInitialVersionParams {
            .initial_salt = std::span<const std::uint8_t>(kQuicInitialSaltV2.data(), kQuicInitialSaltV2.size()),
            .key_label = "quicv2 key",
            .iv_label = "quicv2 iv",
            .hp_label = "quicv2 hp",
            .initial_packet_type_bits = 1U,
        };
    case kQuicVersionDraft29:
        return QuicInitialVersionParams {
            .initial_salt = std::span<const std::uint8_t>(kQuicInitialSaltDraft29.data(), kQuicInitialSaltDraft29.size()),
            .key_label = "quic key",
            .iv_label = "quic iv",
            .hp_label = "quic hp",
            .initial_packet_type_bits = 0U,
        };
    default:
        return std::nullopt;
    }
}
std::uint16_t read_be16(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                      static_cast<std::uint16_t>(bytes[offset + 1U]));
}

std::uint32_t read_be24(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 2U]);
}

std::uint32_t read_be32(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 3U]);
}

bool is_plausible_service_name_char(const char value) noexcept {
    const auto byte = static_cast<unsigned char>(value);
    return std::isalnum(byte) != 0 || value == '.' || value == '-' || value == '_';
}

bool is_plausible_service_name(const std::string_view value) noexcept {
    if (value.empty()) {
        return false;
    }

    for (const auto character : value) {
        if (!is_plausible_service_name_char(character)) {
            return false;
        }
    }

    return true;
}

std::string_view bytes_as_text(std::span<const std::uint8_t> bytes) {
    return std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::optional<std::uint64_t> read_varint(std::span<const std::uint8_t> bytes, std::size_t& offset) {
    if (offset >= bytes.size()) {
        return std::nullopt;
    }

    const auto first = bytes[offset];
    const auto encoded_length = static_cast<std::size_t>(1U << ((first >> 6U) & 0x03U));
    if (offset + encoded_length > bytes.size()) {
        return std::nullopt;
    }

    std::uint64_t value = static_cast<std::uint64_t>(first & 0x3FU);
    for (std::size_t index = 1U; index < encoded_length; ++index) {
        value = (value << 8U) | static_cast<std::uint64_t>(bytes[offset + index]);
    }

    offset += encoded_length;
    return value;
}

std::vector<std::uint8_t> tls_hkdf_label(const std::uint16_t length, const std::string_view label) {
    constexpr std::string_view prefix = "tls13 ";

    std::vector<std::uint8_t> info {};
    info.reserve(2U + 1U + prefix.size() + label.size() + 1U);
    info.push_back(static_cast<std::uint8_t>((length >> 8U) & 0xFFU));
    info.push_back(static_cast<std::uint8_t>(length & 0xFFU));
    info.push_back(static_cast<std::uint8_t>(prefix.size() + label.size()));
    info.insert(info.end(), prefix.begin(), prefix.end());
    info.insert(info.end(), label.begin(), label.end());
    info.push_back(0x00U);
    return info;
}

#ifdef _WIN32

class BCryptAlgorithm final {
public:
    BCryptAlgorithm(const wchar_t* algorithm, const ULONG flags = 0) {
        if (BCryptOpenAlgorithmProvider(&handle_, algorithm, nullptr, flags) < 0) {
            handle_ = nullptr;
        }
    }

    ~BCryptAlgorithm() {
        if (handle_ != nullptr) {
            BCryptCloseAlgorithmProvider(handle_, 0);
        }
    }

    BCryptAlgorithm(const BCryptAlgorithm&) = delete;
    BCryptAlgorithm& operator=(const BCryptAlgorithm&) = delete;

    [[nodiscard]] BCRYPT_ALG_HANDLE get() const noexcept {
        return handle_;
    }

    [[nodiscard]] bool valid() const noexcept {
        return handle_ != nullptr;
    }

private:
    BCRYPT_ALG_HANDLE handle_ {nullptr};
};

class BCryptKey final {
public:
    BCryptKey(BCRYPT_ALG_HANDLE algorithm, std::span<const std::uint8_t> key_bytes) {
        if (algorithm == nullptr) {
            return;
        }

        ULONG object_length = 0;
        ULONG result_size = 0;
        if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_length), sizeof(object_length), &result_size, 0) < 0) {
            return;
        }

        object_.resize(object_length);
        if (BCryptGenerateSymmetricKey(
                algorithm,
                &handle_,
                object_.empty() ? nullptr : object_.data(),
                static_cast<ULONG>(object_.size()),
                const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(key_bytes.data())),
                static_cast<ULONG>(key_bytes.size()),
                0) < 0) {
            handle_ = nullptr;
            object_.clear();
        }
    }

    ~BCryptKey() {
        if (handle_ != nullptr) {
            BCryptDestroyKey(handle_);
        }
    }

    BCryptKey(const BCryptKey&) = delete;
    BCryptKey& operator=(const BCryptKey&) = delete;

    [[nodiscard]] BCRYPT_KEY_HANDLE get() const noexcept {
        return handle_;
    }

    [[nodiscard]] bool valid() const noexcept {
        return handle_ != nullptr;
    }

private:
    BCRYPT_KEY_HANDLE handle_ {nullptr};
    std::vector<std::uint8_t> object_ {};
};

std::optional<std::vector<std::uint8_t>> hmac_sha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data) {
    BCryptAlgorithm algorithm {BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG};
    if (!algorithm.valid()) {
        return std::nullopt;
    }

    ULONG object_length = 0;
    ULONG object_result = 0;
    if (BCryptGetProperty(algorithm.get(), BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_length), sizeof(object_length), &object_result, 0) < 0) {
        return std::nullopt;
    }

    ULONG hash_length = 0;
    ULONG hash_result = 0;
    if (BCryptGetProperty(algorithm.get(), BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_length), sizeof(hash_length), &hash_result, 0) < 0) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> object(object_length);
    std::vector<std::uint8_t> hash(hash_length);
    BCRYPT_HASH_HANDLE handle = nullptr;
    if (BCryptCreateHash(
            algorithm.get(),
            &handle,
            object.empty() ? nullptr : object.data(),
            static_cast<ULONG>(object.size()),
            const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(key.data())),
            static_cast<ULONG>(key.size()),
            0) < 0) {
        return std::nullopt;
    }

    const auto destroy_hash = [&handle]() {
        if (handle != nullptr) {
            BCryptDestroyHash(handle);
            handle = nullptr;
        }
    };

    if (!data.empty() && BCryptHashData(handle, const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(data.data())), static_cast<ULONG>(data.size()), 0) < 0) {
        destroy_hash();
        return std::nullopt;
    }

    if (BCryptFinishHash(handle, hash.data(), static_cast<ULONG>(hash.size()), 0) < 0) {
        destroy_hash();
        return std::nullopt;
    }

    destroy_hash();
    return hash;
}

std::optional<std::vector<std::uint8_t>> hkdf_extract(std::span<const std::uint8_t> salt, std::span<const std::uint8_t> ikm) {
    return hmac_sha256(salt, ikm);
}

std::optional<std::vector<std::uint8_t>> hkdf_expand(std::span<const std::uint8_t> prk,
                                                     std::span<const std::uint8_t> info,
                                                     const std::size_t length) {
    std::vector<std::uint8_t> output {};
    output.reserve(length);
    std::vector<std::uint8_t> previous {};
    std::uint8_t counter = 1U;

    while (output.size() < length) {
        std::vector<std::uint8_t> input {};
        input.reserve(previous.size() + info.size() + 1U);
        input.insert(input.end(), previous.begin(), previous.end());
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter);

        const auto block = hmac_sha256(prk, input);
        if (!block.has_value()) {
            return std::nullopt;
        }

        previous = *block;
        const auto bytes_to_copy = std::min(previous.size(), length - output.size());
        output.insert(output.end(), previous.begin(), previous.begin() + static_cast<std::ptrdiff_t>(bytes_to_copy));
        ++counter;
    }

    return output;
}

std::optional<std::vector<std::uint8_t>> hkdf_expand_label(std::span<const std::uint8_t> secret,
                                                           const std::string_view label,
                                                           const std::size_t length) {
    const auto info = tls_hkdf_label(static_cast<std::uint16_t>(length), label);
    return hkdf_expand(secret, info, length);
}

bool set_aes_chaining_mode(BCRYPT_ALG_HANDLE algorithm, const wchar_t* mode) {
    return BCryptSetProperty(
        algorithm,
        BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(mode)),
        static_cast<ULONG>((std::wcslen(mode) + 1U) * sizeof(wchar_t)),
        0) >= 0;
}

std::optional<std::array<std::uint8_t, 16>> aes_ecb_encrypt_block(std::span<const std::uint8_t> key,
                                                                  std::span<const std::uint8_t> block) {
    if (key.size() != kQuicAes128KeySize || block.size() != 16U) {
        return std::nullopt;
    }

    BCryptAlgorithm algorithm {BCRYPT_AES_ALGORITHM};
    if (!algorithm.valid() || !set_aes_chaining_mode(algorithm.get(), BCRYPT_CHAIN_MODE_ECB)) {
        return std::nullopt;
    }

    BCryptKey aes_key {algorithm.get(), key};
    if (!aes_key.valid()) {
        return std::nullopt;
    }

    std::array<std::uint8_t, 16> output {};
    ULONG bytes_written = 0;
    if (BCryptEncrypt(
            aes_key.get(),
            const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(block.data())),
            static_cast<ULONG>(block.size()),
            nullptr,
            nullptr,
            0,
            output.data(),
            static_cast<ULONG>(output.size()),
            &bytes_written,
            0) < 0 || bytes_written != output.size()) {
        return std::nullopt;
    }

    return output;
}

std::optional<std::vector<std::uint8_t>> aes_128_gcm_decrypt(std::span<const std::uint8_t> key,
                                                             std::span<const std::uint8_t> nonce,
                                                             std::span<const std::uint8_t> aad,
                                                             std::span<const std::uint8_t> ciphertext,
                                                             std::span<const std::uint8_t> tag) {
    if (key.size() != kQuicAes128KeySize || nonce.size() != kQuicIvSize || tag.size() != kQuicTagSize) {
        return std::nullopt;
    }

    BCryptAlgorithm algorithm {BCRYPT_AES_ALGORITHM};
    if (!algorithm.valid() || !set_aes_chaining_mode(algorithm.get(), BCRYPT_CHAIN_MODE_GCM)) {
        return std::nullopt;
    }

    BCryptKey aes_key {algorithm.get(), key};
    if (!aes_key.valid()) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> plaintext(ciphertext.size());
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(nonce.data()));
    auth_info.cbNonce = static_cast<ULONG>(nonce.size());
    auth_info.pbAuthData = const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(aad.data()));
    auth_info.cbAuthData = static_cast<ULONG>(aad.size());
    auth_info.pbTag = const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(tag.data()));
    auth_info.cbTag = static_cast<ULONG>(tag.size());

    ULONG bytes_written = 0;
    if (BCryptDecrypt(
            aes_key.get(),
            const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(ciphertext.data())),
            static_cast<ULONG>(ciphertext.size()),
            &auth_info,
            nullptr,
            0,
            plaintext.empty() ? nullptr : plaintext.data(),
            static_cast<ULONG>(plaintext.size()),
            &bytes_written,
            0) < 0 || bytes_written != plaintext.size()) {
        return std::nullopt;
    }

    return plaintext;
}

#else

class EvpCipherContext final {
public:
    EvpCipherContext()
        : handle_(EVP_CIPHER_CTX_new()) {
    }

    ~EvpCipherContext() {
        if (handle_ != nullptr) {
            EVP_CIPHER_CTX_free(handle_);
        }
    }

    EvpCipherContext(const EvpCipherContext&) = delete;
    EvpCipherContext& operator=(const EvpCipherContext&) = delete;

    [[nodiscard]] EVP_CIPHER_CTX* get() const noexcept {
        return handle_;
    }

    [[nodiscard]] bool valid() const noexcept {
        return handle_ != nullptr;
    }

private:
    EVP_CIPHER_CTX* handle_ {nullptr};
};

bool fits_openssl_int(const std::size_t size) noexcept {
    return size <= static_cast<std::size_t>(std::numeric_limits<int>::max());
}

std::optional<std::vector<std::uint8_t>> hmac_sha256(std::span<const std::uint8_t> key,
                                                     std::span<const std::uint8_t> data) {
    if (!fits_openssl_int(key.size())) {
        return std::nullopt;
    }

    unsigned int output_length = EVP_MAX_MD_SIZE;
    std::vector<std::uint8_t> output(output_length);

    const auto* result = HMAC(
        EVP_sha256(),
        key.empty() ? nullptr : key.data(),
        static_cast<int>(key.size()),
        data.empty() ? nullptr : data.data(),
        data.size(),
        output.data(),
        &output_length);
    if (result == nullptr || output_length != kQuicInitialSecretSize) {
        return std::nullopt;
    }

    output.resize(output_length);
    return output;
}

std::optional<std::vector<std::uint8_t>> hkdf_extract(std::span<const std::uint8_t> salt,
                                                      std::span<const std::uint8_t> ikm) {
    return hmac_sha256(salt, ikm);
}

std::optional<std::vector<std::uint8_t>> hkdf_expand(std::span<const std::uint8_t> prk,
                                                     std::span<const std::uint8_t> info,
                                                     const std::size_t length) {
    std::vector<std::uint8_t> output {};
    output.reserve(length);
    std::vector<std::uint8_t> previous {};
    std::uint8_t counter = 1U;

    while (output.size() < length) {
        std::vector<std::uint8_t> input {};
        input.reserve(previous.size() + info.size() + 1U);
        input.insert(input.end(), previous.begin(), previous.end());
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter);

        const auto block = hmac_sha256(prk, input);
        if (!block.has_value()) {
            return std::nullopt;
        }

        previous = *block;
        const auto bytes_to_copy = std::min(previous.size(), length - output.size());
        output.insert(output.end(), previous.begin(), previous.begin() + static_cast<std::ptrdiff_t>(bytes_to_copy));
        ++counter;
    }

    return output;
}

std::optional<std::vector<std::uint8_t>> hkdf_expand_label(std::span<const std::uint8_t> secret,
                                                           const std::string_view label,
                                                           const std::size_t length) {
    const auto info = tls_hkdf_label(static_cast<std::uint16_t>(length), label);
    return hkdf_expand(secret, info, length);
}

std::optional<std::array<std::uint8_t, 16>> aes_ecb_encrypt_block(std::span<const std::uint8_t> key,
                                                                  std::span<const std::uint8_t> block) {
    if (key.size() != kQuicAes128KeySize || block.size() != 16U) {
        return std::nullopt;
    }

    EvpCipherContext context {};
    if (!context.valid() ||
        EVP_EncryptInit_ex(context.get(), EVP_aes_128_ecb(), nullptr, key.data(), nullptr) <= 0 ||
        EVP_CIPHER_CTX_set_padding(context.get(), 0) <= 0) {
        return std::nullopt;
    }

    std::array<std::uint8_t, 16> output {};
    int bytes_written = 0;
    int final_bytes = 0;
    if (EVP_EncryptUpdate(context.get(), output.data(), &bytes_written, block.data(), static_cast<int>(block.size())) <= 0 ||
        bytes_written != static_cast<int>(output.size()) ||
        EVP_EncryptFinal_ex(context.get(), output.data() + bytes_written, &final_bytes) <= 0 ||
        final_bytes != 0) {
        return std::nullopt;
    }

    return output;
}

std::optional<std::vector<std::uint8_t>> aes_128_gcm_decrypt(std::span<const std::uint8_t> key,
                                                             std::span<const std::uint8_t> nonce,
                                                             std::span<const std::uint8_t> aad,
                                                             std::span<const std::uint8_t> ciphertext,
                                                             std::span<const std::uint8_t> tag) {
    if (key.size() != kQuicAes128KeySize || nonce.size() != kQuicIvSize || tag.size() != kQuicTagSize ||
        !fits_openssl_int(aad.size()) || !fits_openssl_int(ciphertext.size())) {
        return std::nullopt;
    }

    EvpCipherContext context {};
    if (!context.valid() ||
        EVP_DecryptInit_ex(context.get(), EVP_aes_128_gcm(), nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) <= 0 ||
        EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(), nonce.data()) <= 0) {
        return std::nullopt;
    }

    int bytes_written = 0;
    if (!aad.empty() &&
        EVP_DecryptUpdate(context.get(), nullptr, &bytes_written, aad.data(), static_cast<int>(aad.size())) <= 0) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> plaintext(ciphertext.size());
    int plaintext_length = 0;
    if (!ciphertext.empty() &&
        EVP_DecryptUpdate(
            context.get(),
            plaintext.data(),
            &bytes_written,
            ciphertext.data(),
            static_cast<int>(ciphertext.size())) <= 0) {
        return std::nullopt;
    }
    plaintext_length = bytes_written;

    if (EVP_CIPHER_CTX_ctrl(
            context.get(),
            EVP_CTRL_GCM_SET_TAG,
            static_cast<int>(tag.size()),
            const_cast<std::uint8_t*>(tag.data())) <= 0) {
        return std::nullopt;
    }

    int final_bytes = 0;
    if (EVP_DecryptFinal_ex(context.get(), plaintext.data() + plaintext_length, &final_bytes) <= 0) {
        return std::nullopt;
    }

    plaintext.resize(static_cast<std::size_t>(plaintext_length + final_bytes));
    return plaintext;
}

#endif

struct ParsedClientInitialHeader {
    std::uint32_t version {0U};
    std::span<const std::uint8_t> destination_connection_id {};
    std::span<const std::uint8_t> source_connection_id {};
    std::size_t packet_number_offset {0U};
    std::size_t packet_end {0U};
};

std::optional<ParsedClientInitialHeader> parse_client_initial_header(std::span<const std::uint8_t> udp_payload) {
    if (udp_payload.size() < 7U) {
        return std::nullopt;
    }

    const auto first_byte = udp_payload[0];
    if ((first_byte & 0x80U) == 0U || (first_byte & 0x40U) == 0U) {
        return std::nullopt;
    }

    const auto version = read_be32(udp_payload, 1U);
    const auto version_params = quic_initial_version_params(version);
    if (!version_params.has_value()) {
        return std::nullopt;
    }

    if (((first_byte >> 4U) & 0x03U) != version_params->initial_packet_type_bits) {
        return std::nullopt;
    }

    const auto destination_connection_id_length = static_cast<std::size_t>(udp_payload[5U]);
    if (udp_payload.size() < 6U + destination_connection_id_length + 1U) {
        return std::nullopt;
    }

    const auto destination_connection_id = udp_payload.subspan(6U, destination_connection_id_length);

    std::size_t offset = 6U + destination_connection_id_length;
    const auto source_connection_id_length = static_cast<std::size_t>(udp_payload[offset]);
    ++offset;
    if (offset + source_connection_id_length > udp_payload.size()) {
        return std::nullopt;
    }
    const auto source_connection_id = udp_payload.subspan(offset, source_connection_id_length);
    offset += source_connection_id_length;

    const auto token_length = read_varint(udp_payload, offset);
    if (!token_length.has_value() || offset + *token_length > udp_payload.size()) {
        return std::nullopt;
    }
    offset += static_cast<std::size_t>(*token_length);

    const auto length = read_varint(udp_payload, offset);
    if (!length.has_value()) {
        return std::nullopt;
    }

    const auto packet_number_offset = offset;
    const auto packet_end = packet_number_offset + static_cast<std::size_t>(*length);
    if (packet_end > udp_payload.size() || packet_end <= packet_number_offset) {
        return std::nullopt;
    }

    return ParsedClientInitialHeader {
        .version = version,
        .destination_connection_id = destination_connection_id,
        .source_connection_id = source_connection_id,
        .packet_number_offset = packet_number_offset,
        .packet_end = packet_end,
    };
}

struct UnprotectedInitialHeader {
    std::vector<std::uint8_t> associated_data {};
    std::uint64_t packet_number {0U};
    std::size_t packet_number_length {0U};
};

std::optional<UnprotectedInitialHeader> remove_initial_header_protection(std::span<const std::uint8_t> udp_payload,
                                                                         const ParsedClientInitialHeader& header,
                                                                         std::span<const std::uint8_t> hp_key) {
    if (header.packet_number_offset + 4U + kQuicSampleSize > header.packet_end) {
        return std::nullopt;
    }

    const auto sample = udp_payload.subspan(header.packet_number_offset + 4U, kQuicSampleSize);
    const auto mask_block = aes_ecb_encrypt_block(hp_key, sample);
    if (!mask_block.has_value()) {
        return std::nullopt;
    }

    auto first_byte = static_cast<std::uint8_t>(udp_payload[0] ^ ((*mask_block)[0] & 0x0FU));
    const auto packet_number_length = static_cast<std::size_t>((first_byte & 0x03U) + 1U);
    if (header.packet_number_offset + packet_number_length > header.packet_end) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> associated_data(
        udp_payload.begin(),
        udp_payload.begin() + static_cast<std::ptrdiff_t>(header.packet_number_offset + packet_number_length));
    associated_data[0] = first_byte;

    std::uint64_t packet_number = 0U;
    for (std::size_t index = 0U; index < packet_number_length; ++index) {
        const auto unmasked = static_cast<std::uint8_t>(associated_data[header.packet_number_offset + index] ^ (*mask_block)[index + 1U]);
        associated_data[header.packet_number_offset + index] = unmasked;
        packet_number = (packet_number << 8U) | static_cast<std::uint64_t>(unmasked);
    }

    return UnprotectedInitialHeader {
        .associated_data = std::move(associated_data),
        .packet_number = packet_number,
        .packet_number_length = packet_number_length,
    };
}

std::array<std::uint8_t, kQuicIvSize> build_quic_nonce(std::span<const std::uint8_t> iv, const std::uint64_t packet_number) {
    std::array<std::uint8_t, kQuicIvSize> nonce {};
    std::copy(iv.begin(), iv.end(), nonce.begin());

    for (std::size_t index = 0U; index < 8U; ++index) {
        const auto shift = static_cast<unsigned>((7U - index) * 8U);
        nonce[kQuicIvSize - 8U + index] ^= static_cast<std::uint8_t>((packet_number >> shift) & 0xFFU);
    }

    return nonce;
}

struct CryptoFragment {
    std::uint64_t offset {0U};
    std::vector<std::uint8_t> bytes {};
};

std::optional<std::size_t> read_varint_size(std::span<const std::uint8_t> bytes, std::size_t& offset) {
    const auto value = read_varint(bytes, offset);
    if (!value.has_value() || *value > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return std::nullopt;
    }

    return static_cast<std::size_t>(*value);
}

bool skip_bytes(std::span<const std::uint8_t> bytes, std::size_t& offset, const std::size_t count) {
    if (offset + count > bytes.size()) {
        return false;
    }

    offset += count;
    return true;
}

bool skip_ack_frame(std::span<const std::uint8_t> bytes, std::size_t& offset, const bool has_ecn) {
    const auto largest_ack = read_varint(bytes, offset);
    const auto ack_delay = read_varint(bytes, offset);
    const auto ack_range_count = read_varint_size(bytes, offset);
    const auto first_ack_range = read_varint(bytes, offset);
    if (!largest_ack.has_value() || !ack_delay.has_value() || !ack_range_count.has_value() || !first_ack_range.has_value()) {
        return false;
    }

    for (std::size_t index = 0U; index < *ack_range_count; ++index) {
        const auto gap = read_varint(bytes, offset);
        const auto ack_range_length = read_varint(bytes, offset);
        if (!gap.has_value() || !ack_range_length.has_value()) {
            return false;
        }
    }

    if (!has_ecn) {
        return true;
    }

    const auto ect0_count = read_varint(bytes, offset);
    const auto ect1_count = read_varint(bytes, offset);
    const auto ecn_ce_count = read_varint(bytes, offset);
    return ect0_count.has_value() && ect1_count.has_value() && ecn_ce_count.has_value();
}

bool skip_stream_frame(std::span<const std::uint8_t> bytes, std::size_t& offset, const std::uint8_t frame_type) {
    const auto stream_id = read_varint(bytes, offset);
    if (!stream_id.has_value()) {
        return false;
    }

    const bool has_offset = (frame_type & 0x04U) != 0U;
    const bool has_length = (frame_type & 0x02U) != 0U;

    if (has_offset && !read_varint(bytes, offset).has_value()) {
        return false;
    }

    if (!has_length) {
        offset = bytes.size();
        return true;
    }

    const auto length = read_varint_size(bytes, offset);
    return length.has_value() && skip_bytes(bytes, offset, *length);
}

bool skip_frame_payload(std::span<const std::uint8_t> bytes, std::size_t& offset, const std::uint8_t frame_type) {
    switch (frame_type) {
    case 0x02U:
        return skip_ack_frame(bytes, offset, false);
    case 0x03U:
        return skip_ack_frame(bytes, offset, true);
    case 0x04U:
        return read_varint(bytes, offset).has_value() &&
               read_varint(bytes, offset).has_value() &&
               read_varint(bytes, offset).has_value();
    case 0x05U:
        return read_varint(bytes, offset).has_value() && read_varint(bytes, offset).has_value();
    case 0x07U: {
        const auto token_length = read_varint_size(bytes, offset);
        return token_length.has_value() && skip_bytes(bytes, offset, *token_length);
    }
    case 0x08U:
    case 0x09U:
    case 0x0AU:
    case 0x0BU:
    case 0x0CU:
    case 0x0DU:
    case 0x0EU:
    case 0x0FU:
        return skip_stream_frame(bytes, offset, frame_type);
    case 0x10U:
    case 0x12U:
    case 0x13U:
    case 0x14U:
    case 0x16U:
    case 0x17U:
    case 0x19U:
        return read_varint(bytes, offset).has_value();
    case 0x11U:
    case 0x15U:
        return read_varint(bytes, offset).has_value() && read_varint(bytes, offset).has_value();
    case 0x18U: {
        const auto sequence_number = read_varint(bytes, offset);
        const auto retire_prior_to = read_varint(bytes, offset);
        if (!sequence_number.has_value() || !retire_prior_to.has_value() || offset >= bytes.size()) {
            return false;
        }

        const auto connection_id_length = static_cast<std::size_t>(bytes[offset++]);
        return skip_bytes(bytes, offset, connection_id_length) && skip_bytes(bytes, offset, 16U);
    }
    case 0x1AU:
    case 0x1BU:
        return skip_bytes(bytes, offset, 8U);
    case 0x1CU: {
        const auto error_code = read_varint(bytes, offset);
        const auto triggering_frame_type = read_varint(bytes, offset);
        const auto reason_length = read_varint_size(bytes, offset);
        return error_code.has_value() && triggering_frame_type.has_value() &&
               reason_length.has_value() && skip_bytes(bytes, offset, *reason_length);
    }
    case 0x1DU: {
        const auto error_code = read_varint(bytes, offset);
        const auto reason_length = read_varint_size(bytes, offset);
        return error_code.has_value() && reason_length.has_value() && skip_bytes(bytes, offset, *reason_length);
    }
    case 0x1EU:
        return true;
    default: {
        // Best-effort fallback for extension frame types.
        const auto extension_length = read_varint_size(bytes, offset);
        if (extension_length.has_value()) {
            return skip_bytes(bytes, offset, *extension_length);
        }

        if (offset < bytes.size()) {
            ++offset;
            return true;
        }

        return false;
    }
    }
}

bool collect_crypto_fragments(std::span<const std::uint8_t> plaintext, std::vector<CryptoFragment>& fragments) {
    std::size_t offset = 0U;
    while (offset < plaintext.size()) {
        const auto frame_type = plaintext[offset++];
        if (frame_type == 0x00U || frame_type == 0x01U) {
            continue;
        }

        if (frame_type == 0x06U) {
            const auto crypto_offset = read_varint(plaintext, offset);
            const auto crypto_length = read_varint_size(plaintext, offset);
            if (!crypto_offset.has_value() || !crypto_length.has_value()) {
                return false;
            }

            if (!skip_bytes(plaintext, offset, *crypto_length)) {
                return false;
            }

            const auto crypto_start = offset - *crypto_length;
            fragments.push_back(CryptoFragment {
                .offset = *crypto_offset,
                .bytes = std::vector<std::uint8_t>(
                    plaintext.begin() + static_cast<std::ptrdiff_t>(crypto_start),
                    plaintext.begin() + static_cast<std::ptrdiff_t>(offset)),
            });
            continue;
        }

        if (!skip_frame_payload(plaintext, offset, frame_type)) {
            return false;
        }
    }

    return true;
}

std::vector<std::uint8_t> assemble_crypto_prefix(const std::vector<CryptoFragment>& fragments) {
    std::vector<std::uint8_t> stream_buffer(QuicInitialParser::kMaxCryptoBytes, 0U);
    std::vector<std::uint8_t> covered(QuicInitialParser::kMaxCryptoBytes, 0U);

    // First-write-wins policy for overlapping CRYPTO ranges keeps assembly deterministic.
    for (const auto& fragment : fragments) {
        if (fragment.bytes.empty() ||
            fragment.offset >= static_cast<std::uint64_t>(QuicInitialParser::kMaxCryptoBytes)) {
            continue;
        }

        const auto start = static_cast<std::size_t>(fragment.offset);
        const auto writable = std::min(fragment.bytes.size(), QuicInitialParser::kMaxCryptoBytes - start);
        for (std::size_t index = 0U; index < writable; ++index) {
            const auto absolute_index = start + index;
            if (covered[absolute_index] != 0U) {
                continue;
            }

            stream_buffer[absolute_index] = fragment.bytes[index];
            covered[absolute_index] = 1U;
        }
    }

    std::size_t contiguous_prefix = 0U;
    while (contiguous_prefix < covered.size() && covered[contiguous_prefix] != 0U) {
        ++contiguous_prefix;
    }

    stream_buffer.resize(contiguous_prefix);
    return stream_buffer;
}

std::optional<std::string> extract_tls_client_hello_sni_from_handshake(std::span<const std::uint8_t> handshake_bytes) {
    if (handshake_bytes.size() < 4U || handshake_bytes[0] != 0x01U) {
        return std::nullopt;
    }

    const auto handshake_length = static_cast<std::size_t>(read_be24(handshake_bytes, 1U));
    if (handshake_bytes.size() < 4U + handshake_length) {
        return std::nullopt;
    }

    auto body = handshake_bytes.subspan(4U, handshake_length);
    std::size_t offset = 0U;
    if (body.size() < 34U) {
        return std::nullopt;
    }

    offset += 2U;
    offset += 32U;

    const auto session_id_length = static_cast<std::size_t>(body[offset]);
    ++offset;
    if (body.size() < offset + session_id_length + 2U) {
        return std::nullopt;
    }
    offset += session_id_length;

    const auto cipher_suites_length = static_cast<std::size_t>(read_be16(body, offset));
    offset += 2U;
    if (cipher_suites_length == 0U || body.size() < offset + cipher_suites_length + 1U) {
        return std::nullopt;
    }
    offset += cipher_suites_length;

    const auto compression_methods_length = static_cast<std::size_t>(body[offset]);
    ++offset;
    if (body.size() < offset + compression_methods_length + 2U) {
        return std::nullopt;
    }
    offset += compression_methods_length;

    const auto extensions_length = static_cast<std::size_t>(read_be16(body, offset));
    offset += 2U;
    if (body.size() < offset + extensions_length) {
        return std::nullopt;
    }

    const auto extensions_end = offset + extensions_length;
    while (offset + 4U <= extensions_end) {
        const auto extension_type = read_be16(body, offset);
        const auto extension_length = static_cast<std::size_t>(read_be16(body, offset + 2U));
        offset += 4U;
        if (offset + extension_length > extensions_end) {
            return std::nullopt;
        }

        if (extension_type == 0x0000U) {
            const auto extension = body.subspan(offset, extension_length);
            if (extension.size() < 2U) {
                return std::nullopt;
            }

            const auto list_length = static_cast<std::size_t>(read_be16(extension, 0U));
            if (extension.size() < 2U + list_length) {
                return std::nullopt;
            }

            std::size_t name_offset = 2U;
            while (name_offset + 3U <= 2U + list_length) {
                const auto name_type = extension[name_offset];
                const auto name_length = static_cast<std::size_t>(read_be16(extension, name_offset + 1U));
                name_offset += 3U;
                if (name_offset + name_length > 2U + list_length) {
                    return std::nullopt;
                }

                if (name_type == 0U) {
                    const auto server_name = bytes_as_text(extension.subspan(name_offset, name_length));
                    if (is_plausible_service_name(server_name)) {
                        return std::string(server_name);
                    }
                    return std::nullopt;
                }

                name_offset += name_length;
            }
        }

        offset += extension_length;
    }

    return std::nullopt;
}

}  // namespace

namespace {

std::optional<std::vector<std::uint8_t>> decrypt_initial_plaintext_with_perspective(
    std::span<const std::uint8_t> udp_payload,
    const bool use_server_initial_secret,
    std::span<const std::uint8_t> initial_secret_connection_id_override = {}
) {
    const auto header = parse_client_initial_header(udp_payload);
    if (!header.has_value()) {
        return std::nullopt;
    }

    const auto initial_secret_connection_id = !initial_secret_connection_id_override.empty()
        ? initial_secret_connection_id_override
        : header->destination_connection_id;
    if (initial_secret_connection_id.empty()) {
        return std::nullopt;
    }

    const auto version_params = quic_initial_version_params(header->version);
    if (!version_params.has_value()) {
        return std::nullopt;
    }

    const auto initial_secret = hkdf_extract(version_params->initial_salt, initial_secret_connection_id);
    if (!initial_secret.has_value()) {
        return std::nullopt;
    }

    const auto directional_initial_secret = hkdf_expand_label(
        *initial_secret,
        use_server_initial_secret ? "server in" : "client in",
        kQuicInitialSecretSize
    );
    if (!directional_initial_secret.has_value()) {
        return std::nullopt;
    }

    const auto key = hkdf_expand_label(*directional_initial_secret, version_params->key_label, kQuicAes128KeySize);
    const auto iv = hkdf_expand_label(*directional_initial_secret, version_params->iv_label, kQuicIvSize);
    const auto hp = hkdf_expand_label(*directional_initial_secret, version_params->hp_label, kQuicAes128KeySize);
    if (!key.has_value() || !iv.has_value() || !hp.has_value()) {
        return std::nullopt;
    }

    const auto unprotected_header = remove_initial_header_protection(udp_payload, *header, *hp);
    if (!unprotected_header.has_value()) {
        return std::nullopt;
    }

    const auto ciphertext_offset = header->packet_number_offset + unprotected_header->packet_number_length;
    if (ciphertext_offset + kQuicTagSize > header->packet_end) {
        return std::nullopt;
    }

    const auto ciphertext_length = header->packet_end - ciphertext_offset - kQuicTagSize;
    const auto ciphertext = udp_payload.subspan(ciphertext_offset, ciphertext_length);
    const auto tag = udp_payload.subspan(header->packet_end - kQuicTagSize, kQuicTagSize);
    const auto nonce = build_quic_nonce(*iv, unprotected_header->packet_number);

    return aes_128_gcm_decrypt(*key, nonce, unprotected_header->associated_data, ciphertext, tag);
}

void append_bounded_crypto_fragments(std::vector<CryptoFragment>& destination,
                                     std::vector<CryptoFragment> source,
                                     std::size_t& frame_count) {
    for (auto& fragment : source) {
        if (frame_count >= QuicInitialParser::kMaxCryptoFrames) {
            break;
        }

        if (fragment.offset > static_cast<std::uint64_t>(QuicInitialParser::kMaxCryptoBytes)) {
            continue;
        }

        const auto remaining_u64 = static_cast<std::uint64_t>(QuicInitialParser::kMaxCryptoBytes) - fragment.offset;
        const auto remaining = static_cast<std::size_t>(remaining_u64);
        if (remaining == 0U) {
            continue;
        }

        if (fragment.bytes.size() > remaining) {
            fragment.bytes.resize(remaining);
        }

        if (fragment.bytes.empty()) {
            continue;
        }

        destination.push_back(std::move(fragment));
        ++frame_count;
    }
}

std::optional<std::string> extract_client_initial_sni_from_fragments(std::vector<CryptoFragment> fragments) {
    if (fragments.empty()) {
        return std::nullopt;
    }

    auto crypto_prefix = assemble_crypto_prefix(std::move(fragments));
    if (crypto_prefix.empty()) {
        return std::nullopt;
    }

    if (crypto_prefix.size() > QuicInitialParser::kMaxCryptoBytes) {
        crypto_prefix.resize(QuicInitialParser::kMaxCryptoBytes);
    }

    return extract_tls_client_hello_sni_from_handshake(crypto_prefix);
}

std::optional<std::vector<std::uint8_t>> extract_crypto_prefix_from_fragments(std::vector<CryptoFragment> fragments) {
    if (fragments.empty()) {
        return std::nullopt;
    }

    auto crypto_prefix = assemble_crypto_prefix(std::move(fragments));
    if (crypto_prefix.empty()) {
        return std::nullopt;
    }

    if (crypto_prefix.size() > QuicInitialParser::kMaxCryptoBytes) {
        crypto_prefix.resize(QuicInitialParser::kMaxCryptoBytes);
    }

    return crypto_prefix;
}

}  // namespace

bool QuicInitialParser::is_client_initial_packet(std::span<const std::uint8_t> udp_payload) const noexcept {
    const auto header = parse_client_initial_header(udp_payload);
    return header.has_value() && !header->destination_connection_id.empty();
}

std::optional<std::vector<std::uint8_t>> QuicInitialParser::decrypt_initial_plaintext(
    std::span<const std::uint8_t> udp_payload,
    const bool use_server_initial_secret
) const {
    return decrypt_initial_plaintext_with_perspective(udp_payload, use_server_initial_secret);
}

std::optional<std::vector<std::uint8_t>> QuicInitialParser::decrypt_initial_plaintext(
    std::span<const std::uint8_t> udp_payload,
    const bool use_server_initial_secret,
    std::span<const std::uint8_t> initial_secret_connection_id_override
) const {
    return decrypt_initial_plaintext_with_perspective(
        udp_payload,
        use_server_initial_secret,
        initial_secret_connection_id_override
    );
}

std::optional<std::string> QuicInitialParser::extract_client_initial_sni(std::span<const std::uint8_t> udp_payload) const {
    const auto plaintext = decrypt_initial_plaintext_with_perspective(udp_payload, false);
    if (!plaintext.has_value()) {
        return std::nullopt;
    }

    std::vector<CryptoFragment> packet_fragments {};
    if (!collect_crypto_fragments(*plaintext, packet_fragments)) {
        return std::nullopt;
    }

    std::size_t frame_count = 0U;
    std::vector<CryptoFragment> bounded_fragments {};
    bounded_fragments.reserve(std::min(packet_fragments.size(), kMaxCryptoFrames));
    append_bounded_crypto_fragments(bounded_fragments, std::move(packet_fragments), frame_count);
    return extract_client_initial_sni_from_fragments(std::move(bounded_fragments));
}

std::optional<std::vector<std::uint8_t>> QuicInitialParser::extract_client_initial_crypto_prefix(
    std::span<const std::uint8_t> udp_payload
) const {
    const auto plaintext = decrypt_initial_plaintext_with_perspective(udp_payload, false);
    if (!plaintext.has_value()) {
        return std::nullopt;
    }

    std::vector<CryptoFragment> packet_fragments {};
    if (!collect_crypto_fragments(*plaintext, packet_fragments)) {
        return std::nullopt;
    }

    std::size_t frame_count = 0U;
    std::vector<CryptoFragment> bounded_fragments {};
    bounded_fragments.reserve(std::min(packet_fragments.size(), kMaxCryptoFrames));
    append_bounded_crypto_fragments(bounded_fragments, std::move(packet_fragments), frame_count);
    return extract_crypto_prefix_from_fragments(std::move(bounded_fragments));
}

std::optional<std::string> QuicInitialParser::extract_client_initial_sni(std::span<const std::vector<std::uint8_t>> udp_payloads) const {
    std::size_t initial_packet_count = 0U;
    std::size_t frame_count = 0U;
    std::vector<CryptoFragment> fragments {};

    for (const auto& payload_bytes : udp_payloads) {
        if (initial_packet_count >= kMaxInitialPackets || frame_count >= kMaxCryptoFrames) {
            break;
        }

        const auto payload = std::span<const std::uint8_t>(payload_bytes.data(), payload_bytes.size());
        if (!is_client_initial_packet(payload)) {
            continue;
        }

        ++initial_packet_count;

        const auto plaintext = decrypt_initial_plaintext_with_perspective(payload, false);
        if (!plaintext.has_value()) {
            continue;
        }

        std::vector<CryptoFragment> packet_fragments {};
        if (!collect_crypto_fragments(*plaintext, packet_fragments)) {
            continue;
        }

        append_bounded_crypto_fragments(fragments, std::move(packet_fragments), frame_count);
    }

    return extract_client_initial_sni_from_fragments(std::move(fragments));
}

std::optional<std::vector<std::uint8_t>> QuicInitialParser::extract_client_initial_crypto_prefix(
    std::span<const std::vector<std::uint8_t>> udp_payloads
) const {
    std::size_t initial_packet_count = 0U;
    std::size_t frame_count = 0U;
    std::vector<CryptoFragment> fragments {};

    for (const auto& payload_bytes : udp_payloads) {
        if (initial_packet_count >= kMaxInitialPackets || frame_count >= kMaxCryptoFrames) {
            break;
        }

        const auto payload = std::span<const std::uint8_t>(payload_bytes.data(), payload_bytes.size());
        if (!is_client_initial_packet(payload)) {
            continue;
        }

        ++initial_packet_count;

        const auto plaintext = decrypt_initial_plaintext_with_perspective(payload, false);
        if (!plaintext.has_value()) {
            continue;
        }

        std::vector<CryptoFragment> packet_fragments {};
        if (!collect_crypto_fragments(*plaintext, packet_fragments)) {
            continue;
        }

        append_bounded_crypto_fragments(fragments, std::move(packet_fragments), frame_count);
    }

    return extract_crypto_prefix_from_fragments(std::move(fragments));
}

std::optional<std::string> QuicInitialParser::extract_client_initial_sni_from_crypto_payloads(
    std::span<const std::vector<std::uint8_t>> decrypted_initial_payloads
) const {
    const auto crypto_prefix = extract_crypto_prefix_from_payloads(decrypted_initial_payloads);
    if (!crypto_prefix.has_value()) {
        return std::nullopt;
    }

    return extract_tls_client_hello_sni_from_handshake(*crypto_prefix);
}

std::optional<std::vector<std::uint8_t>> QuicInitialParser::extract_crypto_prefix_from_payloads(
    std::span<const std::vector<std::uint8_t>> decrypted_initial_payloads
) const {
    std::size_t frame_count = 0U;
    std::vector<CryptoFragment> fragments {};

    for (const auto& payload : decrypted_initial_payloads) {
        if (frame_count >= kMaxCryptoFrames) {
            break;
        }

        std::vector<CryptoFragment> packet_fragments {};
        if (!collect_crypto_fragments(std::span<const std::uint8_t>(payload.data(), payload.size()), packet_fragments)) {
            continue;
        }

        append_bounded_crypto_fragments(fragments, std::move(packet_fragments), frame_count);
    }

    return extract_crypto_prefix_from_fragments(std::move(fragments));
}
}  // namespace pfl
