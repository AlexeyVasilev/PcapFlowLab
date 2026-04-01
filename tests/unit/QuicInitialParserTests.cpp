#include <algorithm>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "core/services/QuicInitialParser.h"

namespace pfl::tests {

namespace {

void append_be16(std::vector<std::uint8_t>& bytes, const std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

void append_be24(std::vector<std::uint8_t>& bytes, const std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

void append_quic_varint(std::vector<std::uint8_t>& bytes, const std::uint64_t value) {
    if (value < 64U) {
        bytes.push_back(static_cast<std::uint8_t>(value));
        return;
    }

    if (value < 16384U) {
        const auto encoded = static_cast<std::uint16_t>(0x4000U | static_cast<std::uint16_t>(value));
        bytes.push_back(static_cast<std::uint8_t>((encoded >> 8U) & 0xFFU));
        bytes.push_back(static_cast<std::uint8_t>(encoded & 0xFFU));
        return;
    }

    throw TestFailure("append_quic_varint: unsupported test value");
}

std::vector<std::uint8_t> make_client_hello_handshake(const std::string& host) {
    std::vector<std::uint8_t> body {};
    body.push_back(0x03U);
    body.push_back(0x03U);
    body.insert(body.end(), 32U, 0x11U);

    body.push_back(0x00U);

    append_be16(body, 2U);
    body.push_back(0x13U);
    body.push_back(0x01U);

    body.push_back(0x01U);
    body.push_back(0x00U);

    std::vector<std::uint8_t> sni_extension_data {};
    append_be16(sni_extension_data, static_cast<std::uint16_t>(3U + host.size()));
    sni_extension_data.push_back(0x00U);
    append_be16(sni_extension_data, static_cast<std::uint16_t>(host.size()));
    sni_extension_data.insert(sni_extension_data.end(), host.begin(), host.end());

    std::vector<std::uint8_t> extensions {};
    append_be16(extensions, 0x0000U);
    append_be16(extensions, static_cast<std::uint16_t>(sni_extension_data.size()));
    extensions.insert(extensions.end(), sni_extension_data.begin(), sni_extension_data.end());

    append_be16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<std::uint8_t> handshake {};
    handshake.push_back(0x01U);
    append_be24(handshake, static_cast<std::uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());
    return handshake;
}

std::vector<std::uint8_t> make_crypto_frame_payload(const std::uint64_t offset, std::span<const std::uint8_t> bytes) {
    std::vector<std::uint8_t> payload {};
    payload.push_back(0x06U);
    append_quic_varint(payload, offset);
    append_quic_varint(payload, static_cast<std::uint64_t>(bytes.size()));
    payload.insert(payload.end(), bytes.begin(), bytes.end());
    return payload;
}

void append_crypto_frame(std::vector<std::uint8_t>& payload, const std::uint64_t offset, std::span<const std::uint8_t> bytes) {
    const auto frame = make_crypto_frame_payload(offset, bytes);
    payload.insert(payload.end(), frame.begin(), frame.end());
}

}  // namespace

void run_quic_initial_parser_tests() {
    QuicInitialParser parser {};

    {
        const std::string expected_host = "phase2-split.example";
        const auto handshake = make_client_hello_handshake(expected_host);

        const auto split_at = std::min<std::size_t>(20U, handshake.size());
        const auto first_part = std::span<const std::uint8_t>(handshake.data(), split_at);
        const auto second_part = std::span<const std::uint8_t>(handshake.data() + static_cast<std::ptrdiff_t>(split_at), handshake.size() - split_at);

        const std::vector<std::vector<std::uint8_t>> payloads {
            make_crypto_frame_payload(0U, first_part),
            make_crypto_frame_payload(static_cast<std::uint64_t>(split_at), second_part),
        };

        const auto sni = parser.extract_client_initial_sni_from_crypto_payloads(payloads);
        PFL_EXPECT(sni.has_value());
        PFL_EXPECT(*sni == expected_host);
    }

    {
        const std::string expected_host = "phase2-multiframe.example";
        const auto handshake = make_client_hello_handshake(expected_host);
        PFL_EXPECT(handshake.size() > 40U);

        const auto part_a = std::span<const std::uint8_t>(handshake.data(), 12U);
        const auto part_b = std::span<const std::uint8_t>(handshake.data() + 12U, 18U);
        const auto part_c = std::span<const std::uint8_t>(handshake.data() + 30U, 8U);
        const auto part_d = std::span<const std::uint8_t>(handshake.data() + 38U, handshake.size() - 38U);

        std::vector<std::uint8_t> payload_1 {};
        append_crypto_frame(payload_1, 30U, part_c);
        append_crypto_frame(payload_1, 0U, part_a);

        std::vector<std::uint8_t> payload_2 {};
        append_crypto_frame(payload_2, 12U, part_b);

        std::vector<std::uint8_t> payload_3 {};
        append_crypto_frame(payload_3, 38U, part_d);

        const std::vector<std::vector<std::uint8_t>> payloads {
            std::move(payload_1),
            std::move(payload_2),
            std::move(payload_3),
        };

        const auto sni = parser.extract_client_initial_sni_from_crypto_payloads(payloads);
        PFL_EXPECT(sni.has_value());
        PFL_EXPECT(*sni == expected_host);
    }

    {
        const auto handshake = make_client_hello_handshake("incomplete.example");
        const auto truncated_size = std::min<std::size_t>(10U, handshake.size());
        const std::vector<std::vector<std::uint8_t>> payloads {
            make_crypto_frame_payload(0U, std::span<const std::uint8_t>(handshake.data(), truncated_size)),
        };

        const auto sni = parser.extract_client_initial_sni_from_crypto_payloads(payloads);
        PFL_EXPECT(!sni.has_value());
    }

    {
        const std::vector<std::vector<std::uint8_t>> payloads {
            std::vector<std::uint8_t> {0x01U, 0x00U},
            std::vector<std::uint8_t> {0x06U, 0x40U},
        };

        const auto sni = parser.extract_client_initial_sni_from_crypto_payloads(payloads);
        PFL_EXPECT(!sni.has_value());
    }
}

}  // namespace pfl::tests
