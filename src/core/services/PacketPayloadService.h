#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace pfl {

struct TransportPayloadView {
    bool found {false};
    std::size_t offset {0};
    std::size_t length {0};
    std::span<const std::uint8_t> payload {};
};

class PacketPayloadService {
public:
    [[nodiscard]] TransportPayloadView extract_transport_payload_view(std::span<const std::uint8_t> packet_bytes) const;
    [[nodiscard]] TransportPayloadView extract_transport_payload_view(std::span<const std::uint8_t> packet_bytes,
                                                                      std::uint32_t data_link_type) const;
    [[nodiscard]] std::vector<std::uint8_t> extract_transport_payload(std::span<const std::uint8_t> packet_bytes) const;
    [[nodiscard]] std::vector<std::uint8_t> extract_transport_payload(std::span<const std::uint8_t> packet_bytes,
                                                                      std::uint32_t data_link_type) const;
    [[nodiscard]] std::vector<std::uint8_t> extract_packet_details_payload(std::span<const std::uint8_t> packet_bytes) const;
    [[nodiscard]] std::vector<std::uint8_t> extract_packet_details_payload(std::span<const std::uint8_t> packet_bytes,
                                                                           std::uint32_t data_link_type) const;
};

}  // namespace pfl
