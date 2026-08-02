#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "app/session/SessionFormatting.h"

namespace pfl {
class CaptureSession;
}

namespace pfl::session_detail {

struct SelectedPacketSummaryPreparation {
    std::optional<std::uint64_t> flow_packet_index {};
    std::optional<std::uint32_t> transport_payload_length {};
    std::optional<std::uint32_t> original_transport_payload_length {};
    std::vector<std::uint8_t> transport_payload {};
    std::string protocol_details_text {};
    std::vector<std::string> checksum_summary_lines {};
    std::vector<std::string> checksum_warning_lines {};
    std::vector<std::uint8_t> packet_data_preview {};
    TlsInspectionParserContext tls_initial_parser_context {};
    std::vector<TlsSelectedPacketRecordContext> reconstructed_tls_records {};
    std::vector<PacketSummaryLayer> tls_summary_layers {};
    std::optional<QuicPresentationResult> quic_presentation {};
    std::optional<PacketDataPresentation> packet_data {};

    // Creates short-lived spans/views over this owner's bounded buffers for
    // immediate Summary formatting. Callers should not retain the returned
    // PacketSummaryOptions beyond the owner's lifetime.
    [[nodiscard]] PacketSummaryOptions make_options() const;
};

SelectedPacketSummaryPreparation prepare_selected_packet_summary(
    CaptureSession& session,
    const PacketDetails& details,
    const PacketRef& packet,
    std::optional<std::size_t> flow_index,
    std::optional<std::uint64_t> flow_packet_index,
    std::optional<std::size_t> loaded_packet_window_count,
    std::string protocol_details_text,
    std::optional<std::uint32_t> transport_payload_length = {},
    std::optional<std::uint32_t> original_transport_payload_length = {},
    std::vector<std::string> checksum_summary_lines = {},
    std::vector<std::string> checksum_warning_lines = {}
);

}  // namespace pfl::session_detail
