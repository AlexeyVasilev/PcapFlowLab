#include "app/session/SelectedStreamItemDataPresentation.h"

#include <algorithm>
#include <limits>
#include <string_view>
#include <utility>

#include "app/session/CaptureSession.h"
#include "app/session/SelectedFlowPacketSemantics.h"
#include "app/session/SessionHttpReconstruction.h"
#include "app/session/SessionTlsPresentation.h"
#include "core/decode/PacketDecodeSupport.h"
#include "core/services/HexDumpService.h"
#include "core/services/PacketPayloadService.h"

namespace pfl::session_detail {

namespace {

constexpr std::size_t kTlsRecordHeaderSize = 5U;

std::string format_byte_count(const std::uint64_t count) {
    return std::to_string(count) + (count == 1U ? " byte" : " bytes");
}

std::string status_prefix(const StreamItemDataState state) {
    switch (state) {
    case StreamItemDataState::complete:
        return "Complete";
    case StreamItemDataState::partial:
        return "Partial";
    case StreamItemDataState::truncated:
        return "Truncated";
    case StreamItemDataState::window_incomplete:
        return "Window incomplete";
    case StreamItemDataState::synthetic:
        return "Synthetic item";
    case StreamItemDataState::unavailable:
    default:
        return "Item data unavailable";
    }
}

std::string join_status_parts(const std::vector<std::string>& parts) {
    std::string text {};
    for (const auto& part : parts) {
        if (part.empty()) {
            continue;
        }
        if (!text.empty()) {
            text += " • ";
        }
        text += part;
    }
    return text;
}

SelectedStreamItemDataPresentation make_unavailable_presentation(
    const std::uint64_t stream_item_index,
    const StreamItemDataSemanticKind semantic_kind,
    const StreamItemDataState state,
    std::string reason
) {
    return SelectedStreamItemDataPresentation {
        .stream_item_index = stream_item_index,
        .semantic_kind = semantic_kind,
        .source_kind = StreamItemDataSourceKind::unavailable,
        .state = state,
        .assembly_kind = StreamItemDataAssemblyKind::packet_local,
        .available_length = 0U,
        .declared_length = std::nullopt,
        .captured_packet_range = std::nullopt,
        .contributing_unit_count = std::nullopt,
        .contributing_unit_kind = std::nullopt,
        .quic_crypto_stream_offset = std::nullopt,
        .owned_bytes = {},
        .unavailable_reason = std::move(reason),
    };
}

bool is_quic_packet_semantic(const QuicStreamItemSemanticKind semantic_kind) noexcept {
    switch (semantic_kind) {
    case QuicStreamItemSemanticKind::coarse_initial:
    case QuicStreamItemSemanticKind::zero_rtt:
    case QuicStreamItemSemanticKind::handshake:
    case QuicStreamItemSemanticKind::protected_payload:
    case QuicStreamItemSemanticKind::retry:
    case QuicStreamItemSemanticKind::version_negotiation:
        return true;
    default:
        return false;
    }
}

bool is_quic_frame_semantic(const QuicStreamItemSemanticKind semantic_kind) noexcept {
    return semantic_kind == QuicStreamItemSemanticKind::initial_ack ||
        semantic_kind == QuicStreamItemSemanticKind::initial_crypto;
}

bool is_structured_http_row(const StreamItemRow& row) noexcept {
    return row.http_summary.has_value();
}

bool is_packet_backed_tcp_payload_row(const StreamItemRow& row) noexcept {
    return row.semantic_family == StreamItemSemanticFamily::generic &&
        row.generic_summary.has_value() &&
        row.generic_summary->semantic_kind == GenericStreamItemSemanticKind::tcp_payload &&
        row.generic_summary->diagnostic.empty() &&
        row.tls_semantic_kind == TlsStreamItemSemanticKind::none &&
        !row.http_summary.has_value() &&
        !row.quic_stream_presentation.has_value() &&
        !row.arp_summary.has_value();
}

std::optional<std::uint32_t> tls_declared_length(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.size() < kTlsRecordHeaderSize) {
        return std::nullopt;
    }

    const auto record_length =
        (static_cast<std::uint32_t>(bytes[3]) << 8U) | static_cast<std::uint32_t>(bytes[4]);
    return static_cast<std::uint32_t>(kTlsRecordHeaderSize) + record_length;
}

StreamItemDataState tls_row_state(
    const StreamItemRow& row,
    const StreamMaterializationStability stability,
    const std::optional<std::uint32_t> declared_length
) noexcept {
    if (row.tls_semantic_kind == TlsStreamItemSemanticKind::gap) {
        return StreamItemDataState::synthetic;
    }
    if (stability == StreamMaterializationStability::window_incomplete) {
        return StreamItemDataState::window_incomplete;
    }
    if (row.has_constricted_contribution ||
        (declared_length.has_value() && *declared_length > row.summary_payload_bytes.size())) {
        return StreamItemDataState::truncated;
    }
    if (row.tls_semantic_kind == TlsStreamItemSemanticKind::partial_record ||
        row.tls_semantic_kind == TlsStreamItemSemanticKind::partial_payload) {
        return StreamItemDataState::partial;
    }
    return StreamItemDataState::complete;
}

std::optional<std::uint32_t> packet_local_tls_offset(
    const CaptureSession& session,
    const std::size_t flow_index,
    const PacketRef& packet,
    const StreamItemRow& row,
    const std::uint32_t intra_packet_ordinal
) {
    const auto payload_bytes = session.read_selected_flow_transport_payload(flow_index, packet);
    if (payload_bytes.empty()) {
        return std::nullopt;
    }

    const auto packet_items = build_tls_stream_items_for_packet(
        packet.packet_index,
        std::span<const std::uint8_t>(payload_bytes.data(), payload_bytes.size())
    );
    if (!packet_items.handled || intra_packet_ordinal >= packet_items.items.size()) {
        return std::nullopt;
    }

    std::size_t payload_offset = 0U;
    for (std::uint32_t ordinal = 0U; ordinal < intra_packet_ordinal; ++ordinal) {
        payload_offset += packet_items.items[ordinal].byte_count;
    }

    const auto& resolved_item = packet_items.items[intra_packet_ordinal];
    if (resolved_item.semantic_kind != row.tls_semantic_kind ||
        resolved_item.byte_count != row.byte_count) {
        return std::nullopt;
    }

    const auto details = session.read_packet_details(packet);
    if (!details.has_value() || !details->effective_transport_payload.has_value()) {
        return std::nullopt;
    }

    const auto payload_base_offset = static_cast<std::size_t>(details->effective_transport_payload->payload_offset);
    if (payload_offset > std::numeric_limits<std::uint32_t>::max() ||
        payload_base_offset > std::numeric_limits<std::uint32_t>::max() - payload_offset) {
        return std::nullopt;
    }

    return static_cast<std::uint32_t>(payload_base_offset + payload_offset);
}

std::optional<StreamItemCapturedPacketRange> make_captured_packet_range(
    const PacketRef& packet,
    const std::size_t captured_packet_size,
    const std::size_t offset,
    const std::size_t available_length,
    const std::optional<std::uint32_t> declared_length
) {
    if (offset > captured_packet_size ||
        available_length > captured_packet_size - offset ||
        offset > std::numeric_limits<std::uint32_t>::max() ||
        available_length > std::numeric_limits<std::uint32_t>::max()) {
        return std::nullopt;
    }

    return StreamItemCapturedPacketRange {
        .packet_index = packet.packet_index,
        .offset = static_cast<std::uint32_t>(offset),
        .available_length = static_cast<std::uint32_t>(available_length),
        .declared_length = declared_length,
    };
}

std::optional<StreamItemCapturedPacketRange> make_transport_packet_range(
    const CaptureSession& session,
    const PacketRef& packet,
    const std::size_t payload_offset,
    const std::size_t available_length,
    const std::optional<std::uint32_t> declared_length
) {
    const auto packet_bytes = session.read_packet_data(packet);
    if (packet_bytes.empty()) {
        return std::nullopt;
    }

    const auto details = session.read_packet_details(packet);
    if (!details.has_value() || !details->effective_transport_payload.has_value()) {
        return std::nullopt;
    }

    const auto& effective_payload = *details->effective_transport_payload;
    if (payload_offset > effective_payload.captured_payload_length ||
        available_length > effective_payload.captured_payload_length - payload_offset) {
        return std::nullopt;
    }

    const auto absolute_offset = static_cast<std::size_t>(effective_payload.payload_offset) + payload_offset;
    if (absolute_offset < payload_offset) {
        return std::nullopt;
    }

    return make_captured_packet_range(
        packet,
        packet_bytes.size(),
        absolute_offset,
        available_length,
        declared_length
    );
}

SelectedStreamItemDataPresentation build_tls_presentation(
    const CaptureSession& session,
    const std::size_t flow_index,
    const StreamItemRow& row,
    const StreamMaterializationStability stability,
    const std::uint32_t intra_packet_ordinal
) {
    if (row.tls_semantic_kind == TlsStreamItemSemanticKind::gap) {
        return make_unavailable_presentation(
            row.stream_item_index,
            StreamItemDataSemanticKind::tls_record,
            StreamItemDataState::synthetic,
            "Synthetic TLS gap rows do not own bytes."
        );
    }

    const auto declared_length = tls_declared_length(std::span<const std::uint8_t>(
        row.summary_payload_bytes.data(),
        row.summary_payload_bytes.size()
    ));
    const auto state = tls_row_state(row, stability, declared_length);
    const auto assembly_kind = row.packet_count > 1U
        ? StreamItemDataAssemblyKind::reassembled
        : StreamItemDataAssemblyKind::packet_local;

    if (row.packet_count == 1U && !row.packet_indices.empty()) {
        if (const auto packet = session.find_packet(row.packet_indices.front()); packet.has_value()) {
            if (const auto offset = packet_local_tls_offset(
                    session,
                    flow_index,
                    *packet,
                    row,
                    intra_packet_ordinal
                );
                offset.has_value()) {
                return SelectedStreamItemDataPresentation {
                    .stream_item_index = row.stream_item_index,
                    .semantic_kind = StreamItemDataSemanticKind::tls_record,
                    .source_kind = StreamItemDataSourceKind::captured_packet_range,
                    .state = state,
                    .assembly_kind = StreamItemDataAssemblyKind::packet_local,
                    .available_length = static_cast<std::uint32_t>(row.summary_payload_bytes.size()),
                    .declared_length = declared_length,
                    .captured_packet_range = StreamItemCapturedPacketRange {
                        .packet_index = packet->packet_index,
                        .offset = *offset,
                        .available_length = static_cast<std::uint32_t>(row.summary_payload_bytes.size()),
                        .declared_length = declared_length,
                    },
                    .contributing_unit_count = std::nullopt,
                    .contributing_unit_kind = std::nullopt,
                    .quic_crypto_stream_offset = std::nullopt,
                    .owned_bytes = {},
                    .unavailable_reason = {},
                };
            }
        }
    }

    return SelectedStreamItemDataPresentation {
        .stream_item_index = row.stream_item_index,
        .semantic_kind = StreamItemDataSemanticKind::tls_record,
        .source_kind = StreamItemDataSourceKind::retained_item_bytes,
        .state = state,
        .assembly_kind = assembly_kind,
        .available_length = static_cast<std::uint32_t>(row.summary_payload_bytes.size()),
        .declared_length = declared_length,
        .captured_packet_range = std::nullopt,
        .contributing_unit_count = row.packet_count > 1U
            ? std::optional<std::uint32_t> {static_cast<std::uint32_t>(row.packet_count)}
            : std::nullopt,
        .contributing_unit_kind = row.packet_count > 1U
            ? std::optional<StreamItemDataContributionUnitKind> {StreamItemDataContributionUnitKind::tcp_segment}
            : std::nullopt,
        .quic_crypto_stream_offset = std::nullopt,
        .owned_bytes = row.summary_payload_bytes,
        .unavailable_reason = {},
    };
}

SelectedStreamItemDataPresentation build_http_presentation(
    const StreamItemRow& row,
    const StreamMaterializationStability stability
) {
    const auto state = row.byte_count == 0U
        ? StreamItemDataState::synthetic
        : (stability == StreamMaterializationStability::window_incomplete
            ? StreamItemDataState::window_incomplete
            : StreamItemDataState::unavailable);
    const auto reason = row.byte_count == 0U
        ? "Synthetic HTTP gap rows do not own bytes."
        : "HTTP stream rows currently retain formatted preview text but not authoritative item bytes.";
    return make_unavailable_presentation(
        row.stream_item_index,
        StreamItemDataSemanticKind::http_message,
        state,
        reason
    );
}

SelectedStreamItemDataPresentation build_quic_packet_presentation(
    const CaptureSession& session,
    const std::size_t flow_index,
    const StreamItemRow& row
) {
    static_cast<void>(flow_index);
    if (!row.quic_stream_presentation.has_value() || row.packet_indices.empty()) {
        return make_unavailable_presentation(
            row.stream_item_index,
            StreamItemDataSemanticKind::quic_packet,
            StreamItemDataState::unavailable,
            "The QUIC packet row is missing structured packet provenance."
        );
    }

    const auto packet = session.find_packet(row.packet_indices.front());
    if (!packet.has_value()) {
        return make_unavailable_presentation(
            row.stream_item_index,
            StreamItemDataSemanticKind::quic_packet,
            StreamItemDataState::unavailable,
            "The source packet for this QUIC item is no longer available."
        );
    }

    const auto& quic_packet = row.quic_stream_presentation->packet;
    const auto declared_length = quic_packet.packet_bytes_consumed <= std::numeric_limits<std::uint32_t>::max()
        ? std::optional<std::uint32_t> {static_cast<std::uint32_t>(quic_packet.packet_bytes_consumed)}
        : std::nullopt;
    const auto packet_range = make_transport_packet_range(
        session,
        *packet,
        quic_packet.udp_payload_offset,
        quic_packet.packet_bytes_consumed,
        declared_length
    );
    if (!packet_range.has_value()) {
        return make_unavailable_presentation(
            row.stream_item_index,
            StreamItemDataSemanticKind::quic_packet,
            StreamItemDataState::unavailable,
            "The QUIC envelope range could not be resolved from the captured UDP payload."
        );
    }

    return SelectedStreamItemDataPresentation {
        .stream_item_index = row.stream_item_index,
        .semantic_kind = StreamItemDataSemanticKind::quic_packet,
        .source_kind = StreamItemDataSourceKind::captured_packet_range,
        .state = StreamItemDataState::complete,
        .assembly_kind = StreamItemDataAssemblyKind::packet_local,
        .available_length = packet_range->available_length,
        .declared_length = packet_range->declared_length,
        .captured_packet_range = packet_range,
        .contributing_unit_count = std::nullopt,
        .contributing_unit_kind = std::nullopt,
        .quic_crypto_stream_offset = std::nullopt,
        .owned_bytes = {},
        .unavailable_reason = {},
    };
}

SelectedStreamItemDataPresentation build_quic_frame_presentation(
    const CaptureSession& session,
    const std::size_t flow_index,
    const StreamItemRow& row
) {
    if (!row.quic_stream_presentation.has_value() || row.packet_indices.empty() ||
        row.quic_stream_presentation->packet.frames.size() != 1U) {
        return make_unavailable_presentation(
            row.stream_item_index,
            StreamItemDataSemanticKind::quic_frame,
            StreamItemDataState::unavailable,
            "The QUIC frame row does not retain a single authoritative frame provenance."
        );
    }

    const auto presentation = session.derive_quic_presentation_for_packet_context(flow_index, row.packet_indices);
    if (!presentation.has_value() ||
        presentation->selected_initial_plaintext_payload.empty() ||
        !presentation->selected_initial_plaintext_packet_index.has_value()) {
        return make_unavailable_presentation(
            row.stream_item_index,
            StreamItemDataSemanticKind::quic_frame,
            StreamItemDataState::unavailable,
            "This QUIC frame does not currently have an authenticated plaintext owner in the bounded selected-flow context."
        );
    }

    const auto& target_packet = row.quic_stream_presentation->packet;
    const auto packet_it = std::find_if(
        presentation->packets.begin(),
        presentation->packets.end(),
        [&](const QuicPresentationPacket& packet) {
            return packet.shell_type == target_packet.shell_type &&
                packet.udp_payload_offset == target_packet.udp_payload_offset &&
                packet.packet_bytes_consumed == target_packet.packet_bytes_consumed;
        }
    );
    if (packet_it == presentation->packets.end()) {
        return make_unavailable_presentation(
            row.stream_item_index,
            StreamItemDataSemanticKind::quic_frame,
            StreamItemDataState::unavailable,
            "The owning QUIC envelope could not be matched inside the bounded selected-flow presentation."
        );
    }

    const auto packet_index = static_cast<std::size_t>(std::distance(presentation->packets.begin(), packet_it));
    if (*presentation->selected_initial_plaintext_packet_index != packet_index) {
        return make_unavailable_presentation(
            row.stream_item_index,
            StreamItemDataSemanticKind::quic_frame,
            StreamItemDataState::unavailable,
            "The selected bounded QUIC plaintext owner belongs to a different envelope."
        );
    }

    const auto& frame = target_packet.frames.front();
    if (frame.frame_offset > presentation->selected_initial_plaintext_payload.size() ||
        frame.frame_length >
            presentation->selected_initial_plaintext_payload.size() - frame.frame_offset ||
        frame.frame_length > std::numeric_limits<std::uint32_t>::max()) {
        return make_unavailable_presentation(
            row.stream_item_index,
            StreamItemDataSemanticKind::quic_frame,
            StreamItemDataState::unavailable,
            "The QUIC frame range falls outside the bounded decrypted Initial plaintext owner."
        );
    }

    auto owned_bytes = std::vector<std::uint8_t> {};
    owned_bytes.reserve(frame.frame_length);
    owned_bytes.insert(
        owned_bytes.end(),
        presentation->selected_initial_plaintext_payload.begin() + static_cast<std::ptrdiff_t>(frame.frame_offset),
        presentation->selected_initial_plaintext_payload.begin() +
            static_cast<std::ptrdiff_t>(frame.frame_offset + frame.frame_length)
    );

    return SelectedStreamItemDataPresentation {
        .stream_item_index = row.stream_item_index,
        .semantic_kind = StreamItemDataSemanticKind::quic_frame,
        .source_kind = StreamItemDataSourceKind::reconstructed_item,
        .state = StreamItemDataState::complete,
        .assembly_kind = StreamItemDataAssemblyKind::packet_local,
        .available_length = static_cast<std::uint32_t>(frame.frame_length),
        .declared_length = std::optional<std::uint32_t> {static_cast<std::uint32_t>(frame.frame_length)},
        .captured_packet_range = std::nullopt,
        .contributing_unit_count = std::nullopt,
        .contributing_unit_kind = std::nullopt,
        .quic_crypto_stream_offset = frame.crypto_offset,
        .owned_bytes = std::move(owned_bytes),
        .unavailable_reason = {},
    };
}

SelectedStreamItemDataPresentation build_tcp_payload_presentation(
    const CaptureSession& session,
    const std::size_t flow_index,
    const StreamItemRow& row
) {
    if (row.packet_indices.size() != 1U) {
        return make_unavailable_presentation(
            row.stream_item_index,
            StreamItemDataSemanticKind::tcp_payload,
            StreamItemDataState::unavailable,
            "This TCP stream item is not packet-backed inside the current bounded row model."
        );
    }

    const auto packet = session.find_packet(row.packet_indices.front());
    if (!packet.has_value()) {
        return make_unavailable_presentation(
            row.stream_item_index,
            StreamItemDataSemanticKind::tcp_payload,
            StreamItemDataState::unavailable,
            "The source packet for this TCP payload item is no longer available."
        );
    }

    const auto details = session.read_packet_details(*packet);
    if (!details.has_value() || !details->effective_transport_payload.has_value()) {
        return make_unavailable_presentation(
            row.stream_item_index,
            StreamItemDataSemanticKind::tcp_payload,
            StreamItemDataState::unavailable,
            "The TCP payload range could not be resolved from the selected-flow packet cache."
        );
    }

    const auto& effective_payload = *details->effective_transport_payload;
    const auto trim_prefix_bytes = session.selected_flow_tcp_payload_trim_prefix_bytes(flow_index, packet->packet_index);
    const auto declared_length = effective_payload.declared_payload_length.has_value() &&
            *effective_payload.declared_payload_length >= trim_prefix_bytes
        ? std::optional<std::uint32_t> {
            static_cast<std::uint32_t>(*effective_payload.declared_payload_length - trim_prefix_bytes)}
        : std::nullopt;
    const auto packet_range = make_transport_packet_range(
        session,
        *packet,
        trim_prefix_bytes,
        row.byte_count,
        declared_length
    );
    if (!packet_range.has_value()) {
        return make_unavailable_presentation(
            row.stream_item_index,
            StreamItemDataSemanticKind::tcp_payload,
            StreamItemDataState::unavailable,
            "The TCP payload range could not be resolved from the selected-flow packet cache."
        );
    }

    const auto state = effective_payload.payload_truncated ||
            (declared_length.has_value() && *declared_length > row.byte_count)
        ? StreamItemDataState::truncated
        : StreamItemDataState::complete;
    return SelectedStreamItemDataPresentation {
        .stream_item_index = row.stream_item_index,
        .semantic_kind = StreamItemDataSemanticKind::tcp_payload,
        .source_kind = StreamItemDataSourceKind::captured_packet_range,
        .state = state,
        .assembly_kind = StreamItemDataAssemblyKind::packet_local,
        .available_length = packet_range->available_length,
        .declared_length = packet_range->declared_length,
        .captured_packet_range = packet_range,
        .contributing_unit_count = std::nullopt,
        .contributing_unit_kind = std::nullopt,
        .quic_crypto_stream_offset = std::nullopt,
        .owned_bytes = {},
        .unavailable_reason = {},
    };
}

SelectedStreamItemDataPresentation build_packet_payload_presentation(
    const CaptureSession& session,
    const std::size_t flow_index,
    const StreamItemRow& row
) {
    static_cast<void>(flow_index);
    if (row.packet_indices.size() != 1U) {
        return make_unavailable_presentation(
            row.stream_item_index,
            StreamItemDataSemanticKind::opaque_payload,
            StreamItemDataState::unavailable,
            "This stream item is not backed by a single captured packet payload."
        );
    }

    const auto packet = session.find_packet(row.packet_indices.front());
    if (!packet.has_value()) {
        return make_unavailable_presentation(
            row.stream_item_index,
            StreamItemDataSemanticKind::opaque_payload,
            StreamItemDataState::unavailable,
            "The source packet for this stream item is no longer available."
        );
    }

    const auto packet_bytes = session.read_packet_data(*packet);
    if (packet_bytes.empty()) {
        return make_unavailable_presentation(
            row.stream_item_index,
            StreamItemDataSemanticKind::opaque_payload,
            StreamItemDataState::unavailable,
            "The captured packet bytes are not available."
        );
    }

    const auto details = session.read_packet_details(*packet);
    if (details.has_value() && details->effective_transport_payload.has_value()) {
        const auto& effective_payload = *details->effective_transport_payload;
        if (row.byte_count <= effective_payload.captured_payload_length) {
            const auto declared_length = effective_payload.declared_payload_length.has_value()
                ? std::optional<std::uint32_t> {*effective_payload.declared_payload_length}
                : std::optional<std::uint32_t> {};
            const auto packet_range = make_transport_packet_range(
                session,
                *packet,
                0U,
                row.byte_count,
                declared_length
            );
            if (packet_range.has_value()) {
                const auto state = effective_payload.payload_truncated ||
                        (declared_length.has_value() && *declared_length > row.byte_count)
                    ? StreamItemDataState::truncated
                    : StreamItemDataState::complete;
                return SelectedStreamItemDataPresentation {
                    .stream_item_index = row.stream_item_index,
                    .semantic_kind = StreamItemDataSemanticKind::opaque_payload,
                    .source_kind = StreamItemDataSourceKind::captured_packet_range,
                    .state = state,
                    .assembly_kind = StreamItemDataAssemblyKind::packet_local,
                    .available_length = packet_range->available_length,
                    .declared_length = packet_range->declared_length,
                    .captured_packet_range = packet_range,
                    .contributing_unit_count = std::nullopt,
                    .contributing_unit_kind = std::nullopt,
                    .quic_crypto_stream_offset = std::nullopt,
                    .owned_bytes = {},
                    .unavailable_reason = {},
                };
            }
        }
    }

    const auto network = detail::parse_network_payload(
        std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
        packet->data_link_type
    );
    if (row.arp_summary.has_value() &&
        network.has_value() &&
        network->protocol_type == detail::kEtherTypeArp) {
        const auto bounded_bytes = network->bounded_packet_end.has_value()
            ? std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()).first(
                std::min(*network->bounded_packet_end, packet_bytes.size()))
            : std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size());
        if (bounded_bytes.size() > network->payload_offset) {
            const auto available_length = bounded_bytes.size() - network->payload_offset;
            std::optional<std::uint32_t> declared_length {};
            if (available_length >= 8U) {
                const auto hardware_size = static_cast<std::size_t>(bounded_bytes[network->payload_offset + 4U]);
                const auto protocol_size = static_cast<std::size_t>(bounded_bytes[network->payload_offset + 5U]);
                const auto declared_length_size = 8U + (2U * hardware_size) + (2U * protocol_size);
                if (declared_length_size <= std::numeric_limits<std::uint32_t>::max()) {
                    declared_length = static_cast<std::uint32_t>(declared_length_size);
                }
            }
            if (row.byte_count <= available_length) {
                const auto packet_range = make_captured_packet_range(
                    *packet,
                    packet_bytes.size(),
                    network->payload_offset,
                    row.byte_count,
                    declared_length
                );
                if (packet_range.has_value()) {
                    const auto state = declared_length.has_value() && *declared_length > row.byte_count
                        ? StreamItemDataState::truncated
                        : StreamItemDataState::complete;
                    return SelectedStreamItemDataPresentation {
                        .stream_item_index = row.stream_item_index,
                        .semantic_kind = StreamItemDataSemanticKind::other,
                        .source_kind = StreamItemDataSourceKind::captured_packet_range,
                        .state = state,
                        .assembly_kind = StreamItemDataAssemblyKind::packet_local,
                        .available_length = packet_range->available_length,
                        .declared_length = packet_range->declared_length,
                        .captured_packet_range = packet_range,
                        .contributing_unit_count = std::nullopt,
                        .contributing_unit_kind = std::nullopt,
                        .quic_crypto_stream_offset = std::nullopt,
                        .owned_bytes = {},
                        .unavailable_reason = {},
                    };
                }
            }
        }
    }

    return make_unavailable_presentation(
        row.stream_item_index,
        StreamItemDataSemanticKind::other,
        StreamItemDataState::unavailable,
        "The selected stream item does not expose an authoritative packet-backed byte range in the current bounded row model."
    );
}

}  // namespace

std::string to_string(const StreamItemDataSourceKind source_kind) {
    switch (source_kind) {
    case StreamItemDataSourceKind::captured_packet_range:
        return "captured_packet_range";
    case StreamItemDataSourceKind::retained_item_bytes:
        return "retained_item_bytes";
    case StreamItemDataSourceKind::reconstructed_item:
        return "reconstructed_item";
    case StreamItemDataSourceKind::unavailable:
    default:
        return "unavailable";
    }
}

std::string to_string(const StreamItemDataState state) {
    switch (state) {
    case StreamItemDataState::complete:
        return "complete";
    case StreamItemDataState::partial:
        return "partial";
    case StreamItemDataState::truncated:
        return "truncated";
    case StreamItemDataState::window_incomplete:
        return "window_incomplete";
    case StreamItemDataState::synthetic:
        return "synthetic";
    case StreamItemDataState::unavailable:
    default:
        return "unavailable";
    }
}

std::string to_string(const StreamItemDataSemanticKind semantic_kind) {
    switch (semantic_kind) {
    case StreamItemDataSemanticKind::tcp_payload:
        return "tcp_payload";
    case StreamItemDataSemanticKind::http_message:
        return "http_message";
    case StreamItemDataSemanticKind::tls_record:
        return "tls_record";
    case StreamItemDataSemanticKind::tls_handshake:
        return "tls_handshake";
    case StreamItemDataSemanticKind::quic_packet:
        return "quic_packet";
    case StreamItemDataSemanticKind::quic_frame:
        return "quic_frame";
    case StreamItemDataSemanticKind::quic_crypto_data:
        return "quic_crypto_data";
    case StreamItemDataSemanticKind::opaque_payload:
        return "opaque_payload";
    case StreamItemDataSemanticKind::other:
    default:
        return "other";
    }
}

std::string to_string(const StreamItemDataAssemblyKind assembly_kind) {
    switch (assembly_kind) {
    case StreamItemDataAssemblyKind::packet_local:
        return "packet_local";
    case StreamItemDataAssemblyKind::reassembled:
        return "reassembled";
    default:
        return "packet_local";
    }
}

std::string to_string(const StreamItemDataContributionUnitKind contribution_unit_kind) {
    switch (contribution_unit_kind) {
    case StreamItemDataContributionUnitKind::tcp_segment:
        return "tcp_segment";
    case StreamItemDataContributionUnitKind::quic_crypto_frame:
        return "quic_crypto_frame";
    default:
        return "tcp_segment";
    }
}

std::string format_selected_stream_item_data_status_text(
    const SelectedStreamItemDataPresentation& presentation
) {
    if (presentation.state == StreamItemDataState::synthetic) {
        return join_status_parts({
            status_prefix(presentation.state),
            presentation.unavailable_reason.empty()
                ? "This Stream item has no byte data."
                : presentation.unavailable_reason,
        });
    }

    if (presentation.source_kind == StreamItemDataSourceKind::unavailable) {
        return join_status_parts({
            status_prefix(presentation.state),
            presentation.unavailable_reason.empty()
                ? "No authoritative item-owned byte sequence is retained for this Stream item."
                : presentation.unavailable_reason,
        });
    }

    std::vector<std::string> parts {};
    parts.push_back(status_prefix(presentation.state));

    if (presentation.contributing_unit_count.has_value() && presentation.contributing_unit_kind.has_value()) {
        const auto count = *presentation.contributing_unit_count;
        const auto source_text = *presentation.contributing_unit_kind ==
                StreamItemDataContributionUnitKind::tcp_segment
            ? "TCP segment"
            : "CRYPTO frame";
        parts.push_back(
            "Reassembled from " + std::to_string(count) + " " +
            source_text + (count == 1U ? "" : "s")
        );
    } else if (presentation.source_kind == StreamItemDataSourceKind::captured_packet_range) {
        parts.push_back("Packet-backed");
    }

    if (presentation.quic_crypto_stream_offset.has_value()) {
        parts.push_back("CRYPTO stream offset: " + std::to_string(*presentation.quic_crypto_stream_offset));
    }

    parts.push_back("Available: " + format_byte_count(presentation.available_length));
    if (presentation.declared_length.has_value()) {
        parts.push_back("Declared: " + format_byte_count(*presentation.declared_length));
    }

    return join_status_parts(parts);
}

SelectedStreamItemDataPresentation derive_selected_stream_item_data_presentation(
    const CaptureSession& session,
    const std::size_t flow_index,
    const ProtocolId flow_protocol,
    const StreamItemRow& row,
    const StreamMaterializationStability stability,
    const std::uint32_t intra_packet_ordinal
) {
    if (row.byte_count == 0U) {
        const auto semantic_kind = row.tls_semantic_kind == TlsStreamItemSemanticKind::gap
            ? StreamItemDataSemanticKind::tls_record
            : (is_structured_http_row(row)
                ? StreamItemDataSemanticKind::http_message
                : StreamItemDataSemanticKind::other);
        return make_unavailable_presentation(
            row.stream_item_index,
            semantic_kind,
            StreamItemDataState::synthetic,
            "This stream row is synthetic and does not own bytes."
        );
    }

    if (row.tls_semantic_kind != TlsStreamItemSemanticKind::none) {
        return build_tls_presentation(session, flow_index, row, stability, intra_packet_ordinal);
    }

    if (row.quic_stream_presentation.has_value()) {
        if (is_quic_frame_semantic(row.quic_stream_presentation->semantic_kind)) {
            return build_quic_frame_presentation(session, flow_index, row);
        }
        if (is_quic_packet_semantic(row.quic_stream_presentation->semantic_kind)) {
            return build_quic_packet_presentation(session, flow_index, row);
        }
    }

    if (is_structured_http_row(row)) {
        return build_http_presentation(row, stability);
    }

    if (flow_protocol == ProtocolId::tcp && is_packet_backed_tcp_payload_row(row)) {
        return build_tcp_payload_presentation(session, flow_index, row);
    }

    if (row.arp_summary.has_value()) {
        return build_packet_payload_presentation(session, flow_index, row);
    }

    return build_packet_payload_presentation(session, flow_index, row);
}

std::optional<std::vector<std::uint8_t>> materialize_selected_stream_item_data(
    const SelectedStreamItemDataPresentation& presentation,
    const std::span<const std::uint8_t> captured_packet_bytes
) {
    switch (presentation.source_kind) {
    case StreamItemDataSourceKind::captured_packet_range: {
        if (!presentation.captured_packet_range.has_value()) {
            return std::nullopt;
        }
        const auto& range = *presentation.captured_packet_range;
        if (range.offset > captured_packet_bytes.size() ||
            range.available_length > captured_packet_bytes.size() - range.offset) {
            return std::nullopt;
        }
        return std::vector<std::uint8_t>(
            captured_packet_bytes.begin() + static_cast<std::ptrdiff_t>(range.offset),
            captured_packet_bytes.begin() +
                static_cast<std::ptrdiff_t>(range.offset + range.available_length)
        );
    }
    case StreamItemDataSourceKind::retained_item_bytes:
    case StreamItemDataSourceKind::reconstructed_item:
        if (presentation.owned_bytes.size() < presentation.available_length) {
            return std::nullopt;
        }
        return presentation.owned_bytes;
    case StreamItemDataSourceKind::unavailable:
    default:
        return std::nullopt;
    }
}

std::optional<std::string> format_selected_stream_item_data_hex_dump(
    const SelectedStreamItemDataPresentation& presentation,
    const std::span<const std::uint8_t> captured_packet_bytes,
    const HexDumpService& hex_dump_service
) {
    const auto materialized = materialize_selected_stream_item_data(presentation, captured_packet_bytes);
    if (!materialized.has_value()) {
        return std::nullopt;
    }

    return hex_dump_service.format(std::span<const std::uint8_t>(materialized->data(), materialized->size()));
}

}  // namespace pfl::session_detail
