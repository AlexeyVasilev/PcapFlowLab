#include <algorithm>
#include <cstddef>
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

void append_be32(std::vector<std::uint8_t>& bytes, const std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

void append_bytes(std::vector<std::uint8_t>& destination, std::span<const std::uint8_t> source) {
    if (source.empty()) {
        return;
    }

    const auto previous_size = destination.size();
    destination.resize(previous_size + source.size());
    std::copy(source.begin(), source.end(), destination.begin() + static_cast<std::ptrdiff_t>(previous_size));
}

void append_bytes(std::vector<std::uint8_t>& destination, const std::string_view source) {
    if (source.empty()) {
        return;
    }

    const auto previous_size = destination.size();
    destination.resize(previous_size + source.size());
    std::copy(source.begin(), source.end(), destination.begin() + static_cast<std::ptrdiff_t>(previous_size));
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

std::vector<std::uint8_t> make_minimal_initial_packet(const std::uint32_t version,
                                                      const std::uint8_t initial_packet_type_bits) {
    std::vector<std::uint8_t> packet {};
    const auto first_byte = static_cast<std::uint8_t>(0xC0U | ((initial_packet_type_bits & 0x03U) << 4U));
    packet.push_back(first_byte);
    append_be32(packet, version);

    packet.push_back(0x08U);
    packet.insert(packet.end(), {0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U});

    packet.push_back(0x00U);
    append_quic_varint(packet, 0U);

    append_quic_varint(packet, 17U);
    packet.push_back(0x00U);
    packet.insert(packet.end(), 16U, 0x00U);
    return packet;
}

std::vector<std::uint8_t> make_client_hello_handshake(const std::string& host) {
    std::vector<std::uint8_t> body {};
    body.reserve(52U + host.size());
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
    sni_extension_data.reserve(5U + host.size());
    append_be16(sni_extension_data, static_cast<std::uint16_t>(3U + host.size()));
    sni_extension_data.push_back(0x00U);
    append_be16(sni_extension_data, static_cast<std::uint16_t>(host.size()));
    append_bytes(sni_extension_data, host);

    std::vector<std::uint8_t> extensions {};
    extensions.reserve(4U + sni_extension_data.size());
    append_be16(extensions, 0x0000U);
    append_be16(extensions, static_cast<std::uint16_t>(sni_extension_data.size()));
    append_bytes(extensions, sni_extension_data);

    append_be16(body, static_cast<std::uint16_t>(extensions.size()));
    append_bytes(body, extensions);

    std::vector<std::uint8_t> handshake {};
    handshake.reserve(4U + body.size());
    handshake.push_back(0x01U);
    append_be24(handshake, static_cast<std::uint32_t>(body.size()));
    append_bytes(handshake, body);
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

void append_ping_frame(std::vector<std::uint8_t>& payload) {
    payload.push_back(0x01U);
}

void append_padding(std::vector<std::uint8_t>& payload, const std::size_t count) {
    for (std::size_t index = 0U; index < count; ++index) {
        payload.push_back(0x00U);
    }
}

void append_ack_frame(std::vector<std::uint8_t>& payload) {
    payload.push_back(0x02U);
    append_quic_varint(payload, 0U);  // largest acknowledged
    append_quic_varint(payload, 0U);  // ack delay
    append_quic_varint(payload, 0U);  // ack range count
    append_quic_varint(payload, 0U);  // first ack range
}

}  // namespace

void run_quic_initial_parser_tests() {
    QuicInitialParser parser {};

    {
        constexpr std::uint32_t kVersionV1 = 0x00000001U;
        constexpr std::uint32_t kVersionV2 = 0x6B3343CFU;
        constexpr std::uint32_t kVersionDraft29 = 0xFF00001DU;
        constexpr std::uint32_t kUnsupportedVersion = 0x0A0B0C0DU;

        const auto v1_packet = make_minimal_initial_packet(kVersionV1, 0U);
        const auto v2_packet = make_minimal_initial_packet(kVersionV2, 1U);
        const auto draft29_packet = make_minimal_initial_packet(kVersionDraft29, 0U);
        const auto unsupported_packet = make_minimal_initial_packet(kUnsupportedVersion, 0U);

        PFL_EXPECT(parser.is_client_initial_packet(std::span<const std::uint8_t>(v1_packet.data(), v1_packet.size())));
        PFL_EXPECT(parser.is_client_initial_packet(std::span<const std::uint8_t>(v2_packet.data(), v2_packet.size())));
        PFL_EXPECT(parser.is_client_initial_packet(std::span<const std::uint8_t>(draft29_packet.data(), draft29_packet.size())));
        PFL_EXPECT(!parser.is_client_initial_packet(std::span<const std::uint8_t>(unsupported_packet.data(), unsupported_packet.size())));
        PFL_EXPECT(!parser.extract_client_initial_sni(std::span<const std::uint8_t>(unsupported_packet.data(), unsupported_packet.size())).has_value());
    }
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
        const std::string expected_host = "single-packet-offset-assembly.example";
        const auto handshake = make_client_hello_handshake(expected_host);
        PFL_EXPECT(handshake.size() > 30U);

        const auto part_a = std::span<const std::uint8_t>(handshake.data(), 9U);
        const auto part_b = std::span<const std::uint8_t>(handshake.data() + 9U, 12U);
        const auto part_c = std::span<const std::uint8_t>(handshake.data() + 21U, handshake.size() - 21U);

        std::vector<std::uint8_t> payload {};
        append_crypto_frame(payload, 21U, part_c);
        append_crypto_frame(payload, 0U, part_a);
        append_crypto_frame(payload, 9U, part_b);

        const std::vector<std::vector<std::uint8_t>> payloads {payload};
        const auto sni = parser.extract_client_initial_sni_from_crypto_payloads(payloads);
        PFL_EXPECT(sni.has_value());
        PFL_EXPECT(*sni == expected_host);
    }

    {
        const std::string expected_host = "out-of-order-packets.example";
        const auto handshake = make_client_hello_handshake(expected_host);
        PFL_EXPECT(handshake.size() > 30U);

        const auto part_a = std::span<const std::uint8_t>(handshake.data(), 11U);
        const auto part_b = std::span<const std::uint8_t>(handshake.data() + 11U, 12U);
        const auto part_c = std::span<const std::uint8_t>(handshake.data() + 23U, handshake.size() - 23U);

        const std::vector<std::vector<std::uint8_t>> payloads {
            make_crypto_frame_payload(23U, part_c),
            make_crypto_frame_payload(0U, part_a),
            make_crypto_frame_payload(11U, part_b),
        };

        const auto sni = parser.extract_client_initial_sni_from_crypto_payloads(payloads);
        PFL_EXPECT(sni.has_value());
        PFL_EXPECT(*sni == expected_host);
    }

    {
        const auto handshake = make_client_hello_handshake("gap-in-crypto-stream.example");
        PFL_EXPECT(handshake.size() > 20U);

        const auto part_a = std::span<const std::uint8_t>(handshake.data(), 8U);
        const auto part_b = std::span<const std::uint8_t>(handshake.data() + 12U, handshake.size() - 12U);

        const std::vector<std::vector<std::uint8_t>> payloads {
            make_crypto_frame_payload(0U, part_a),
            make_crypto_frame_payload(12U, part_b),
        };

        const auto sni = parser.extract_client_initial_sni_from_crypto_payloads(payloads);
        PFL_EXPECT(!sni.has_value());
    }
    {
        const std::string expected_host = "ping-mixed.example";
        const auto handshake = make_client_hello_handshake(expected_host);

        std::vector<std::uint8_t> payload {};
        append_ping_frame(payload);
        append_crypto_frame(payload, 0U, std::span<const std::uint8_t>(handshake.data(), handshake.size()));

        const std::vector<std::vector<std::uint8_t>> payloads {payload};
        const auto sni = parser.extract_client_initial_sni_from_crypto_payloads(payloads);
        PFL_EXPECT(sni.has_value());
        PFL_EXPECT(*sni == expected_host);
    }

    {
        const std::string expected_host = "padding-mixed.example";
        const auto handshake = make_client_hello_handshake(expected_host);

        std::vector<std::uint8_t> payload {};
        append_padding(payload, 6U);
        append_crypto_frame(payload, 0U, std::span<const std::uint8_t>(handshake.data(), handshake.size()));

        const std::vector<std::vector<std::uint8_t>> payloads {payload};
        const auto sni = parser.extract_client_initial_sni_from_crypto_payloads(payloads);
        PFL_EXPECT(sni.has_value());
        PFL_EXPECT(*sni == expected_host);
    }

    {
        const std::string expected_host = "ack-mixed.example";
        const auto handshake = make_client_hello_handshake(expected_host);

        std::vector<std::uint8_t> payload {};
        append_ack_frame(payload);
        append_crypto_frame(payload, 0U, std::span<const std::uint8_t>(handshake.data(), handshake.size()));

        const std::vector<std::vector<std::uint8_t>> payloads {payload};
        const auto sni = parser.extract_client_initial_sni_from_crypto_payloads(payloads);
        PFL_EXPECT(sni.has_value());
        PFL_EXPECT(*sni == expected_host);
    }

    {
        const std::string expected_host = "mixed-multipacket.example";
        const auto handshake = make_client_hello_handshake(expected_host);
        PFL_EXPECT(handshake.size() > 36U);

        const auto part_a = std::span<const std::uint8_t>(handshake.data(), 16U);
        const auto part_b = std::span<const std::uint8_t>(handshake.data() + 16U, 10U);
        const auto part_c = std::span<const std::uint8_t>(handshake.data() + 26U, handshake.size() - 26U);

        std::vector<std::uint8_t> payload_1 {};
        append_ping_frame(payload_1);
        append_padding(payload_1, 4U);
        append_crypto_frame(payload_1, 0U, part_a);

        std::vector<std::uint8_t> payload_2 {};
        append_ack_frame(payload_2);
        append_crypto_frame(payload_2, 16U, part_b);

        std::vector<std::uint8_t> payload_3 {};
        append_ping_frame(payload_3);
        append_padding(payload_3, 2U);
        append_crypto_frame(payload_3, 26U, part_c);

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

