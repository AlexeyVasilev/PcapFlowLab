#include "app/session/SelectedPacketSummaryPreparation.h"

#include <string_view>

#include "app/session/CaptureSession.h"
#include "core/services/DnsPacketProtocolAnalyzer.h"
#include "core/services/FlowHintService.h"
#include "core/services/HttpPacketProtocolAnalyzer.h"
#include "core/services/PacketPayloadService.h"
#include "core/services/TlsInspectionParser.h"

namespace pfl::session_detail {

std::vector<TlsRecordModel> inspect_tls_summary_records(
    std::span<const std::uint8_t> transport_payload_bytes,
    const TlsInspectionParserContext& initial_parser_context,
    bool force_encrypted_handshake_records,
    bool force_encrypted_alert_records
);

TlsInspectionParserContext advance_tls_summary_parser_context(
    const TlsInspectionParserContext& current_context,
    const TlsSelectedPacketRecordContext& reconstructed_record
);

TlsInspectionParserContext selected_packet_starting_tls_initial_context(
    const PacketSummaryOptions& options
);

std::size_t selected_packet_reassembled_tls_prefix_bytes(const PacketSummaryOptions& options);

namespace {

constexpr std::size_t kTlsSummaryRecordHeaderSize = 5U;
constexpr std::size_t kTlsSummaryMinimumPartialHandshakeBytes = 7U;

std::optional<DnsSummaryPresentationKind> dns_summary_presentation_kind_from_hint(
    const std::string_view protocol_hint
) noexcept {
    if (protocol_hint == "mdns") {
        return DnsSummaryPresentationKind::mdns;
    }
    if (protocol_hint == "dns") {
        return DnsSummaryPresentationKind::dns;
    }
    return std::nullopt;
}

std::optional<DnsSummaryPresentationKind> resolve_dns_summary_presentation_kind(
    CaptureSession& session,
    const PacketDetails& details,
    const std::optional<std::size_t> flow_index
) {
    const bool has_meaningful_structured_dns =
        details.dns_message.has_value() &&
        details.dns_message->status != DnsInspectionStatus::not_enough_header;

    if (flow_index.has_value()) {
        if (const auto row = session.flow_row(*flow_index); row.has_value()) {
            if (const auto kind = dns_summary_presentation_kind_from_hint(row->protocol_hint);
                kind.has_value() && (details.has_dns || has_meaningful_structured_dns)) {
                return kind;
            }
        }
    }

    if (details.has_dns) {
        if (packet_matches_mdns_hint(details)) {
            return DnsSummaryPresentationKind::mdns;
        }
        return DnsSummaryPresentationKind::dns;
    }

    if (has_meaningful_structured_dns && packet_matches_mdns_hint(details)) {
        return DnsSummaryPresentationKind::mdns;
    }

    return std::nullopt;
}

bool has_confirmed_tls_summary_context(
    const TlsInspectionParserContext& initial_parser_context
) noexcept {
    return initial_parser_context.semantic_state == TlsInspectionSemanticState::post_change_cipher_spec ||
        initial_parser_context.negotiated_cipher_suite.has_value() ||
        initial_parser_context.negotiated_version.has_value();
}

bool tls_summary_payload_is_owned_by_tls(
    std::span<const std::uint8_t> payload,
    const TlsInspectionParserContext& initial_parser_context
) {
    const auto header = inspect_tls_record_header(payload);
    if (!header.has_value()) {
        return false;
    }

    const bool confirmed_tls_context = has_confirmed_tls_summary_context(initial_parser_context);
    if (header->declared_payload_length == 0U) {
        return header->content_type_kind == TlsRecordContentTypeKind::application_data &&
            confirmed_tls_context;
    }

    if (header->complete_record_available) {
        return true;
    }

    if (confirmed_tls_context) {
        return true;
    }

    return header->content_type_kind == TlsRecordContentTypeKind::handshake &&
        payload.size() >= kTlsSummaryMinimumPartialHandshakeBytes &&
        payload.size() > kTlsSummaryRecordHeaderSize;
}

TransportPayloadDisposition strongest_transport_payload_disposition(
    const TransportPayloadDisposition current,
    const TransportPayloadDisposition candidate
) {
    const auto rank = [](const TransportPayloadDisposition disposition) {
        switch (disposition) {
        case TransportPayloadDisposition::claimed_by_supported_protocol:
            return 4;
        case TransportPayloadDisposition::known_opaque_or_encrypted:
            return 3;
        case TransportPayloadDisposition::unavailable_or_truncated:
            return 2;
        case TransportPayloadDisposition::unclaimed_data:
            return 1;
        case TransportPayloadDisposition::none:
        default:
            return 0;
        }
    };
    return rank(candidate) > rank(current) ? candidate : current;
}

TransportPayloadDisposition classify_quic_payload_ownership(
    const QuicPresentationResult& presentation
) {
    if (presentation.packets.empty()) {
        return TransportPayloadDisposition::none;
    }

    for (const auto& packet : presentation.packets) {
        if (!packet.frames.empty() || !packet.tls_handshakes.empty()) {
            return TransportPayloadDisposition::claimed_by_supported_protocol;
        }
    }

    return TransportPayloadDisposition::known_opaque_or_encrypted;
}

TransportPayloadDisposition classify_tls_record_ownership(
    const TlsRecordModel& record
) {
    if (record.content_type_kind == TlsRecordContentTypeKind::unknown) {
        return TransportPayloadDisposition::none;
    }
    if (record.content_type_kind == TlsRecordContentTypeKind::application_data) {
        return TransportPayloadDisposition::known_opaque_or_encrypted;
    }
    if (record.content_type_kind == TlsRecordContentTypeKind::handshake &&
        record.handshake_payload_kind == TlsHandshakePayloadKind::encrypted_opaque) {
        return TransportPayloadDisposition::known_opaque_or_encrypted;
    }
    if (record.content_type_kind == TlsRecordContentTypeKind::alert &&
        record.alert_payload_kind == TlsAlertPayloadKind::encrypted_opaque) {
        return TransportPayloadDisposition::known_opaque_or_encrypted;
    }
    return TransportPayloadDisposition::claimed_by_supported_protocol;
}

TransportPayloadDisposition classify_tls_records_ownership(
    const std::vector<TlsRecordModel>& records
) {
    auto disposition = TransportPayloadDisposition::none;
    for (const auto& record : records) {
        disposition = strongest_transport_payload_disposition(
            disposition,
            classify_tls_record_ownership(record)
        );
    }
    return disposition;
}

TransportPayloadDisposition classify_reconstructed_tls_ownership(
    const std::vector<TlsSelectedPacketRecordContext>& reconstructed_records
) {
    auto disposition = TransportPayloadDisposition::none;
    for (const auto& record : reconstructed_records) {
        switch (record.semantic_kind) {
        case TlsStreamItemSemanticKind::application_data:
        case TlsStreamItemSemanticKind::encrypted_alert:
        case TlsStreamItemSemanticKind::encrypted_handshake:
            disposition = strongest_transport_payload_disposition(
                disposition,
                TransportPayloadDisposition::known_opaque_or_encrypted
            );
            break;
        case TlsStreamItemSemanticKind::change_cipher_spec:
        case TlsStreamItemSemanticKind::plaintext_handshake:
        case TlsStreamItemSemanticKind::alert:
        case TlsStreamItemSemanticKind::generic_record:
        case TlsStreamItemSemanticKind::partial_record:
        case TlsStreamItemSemanticKind::partial_payload:
        case TlsStreamItemSemanticKind::gap:
            disposition = strongest_transport_payload_disposition(
                disposition,
                TransportPayloadDisposition::claimed_by_supported_protocol
            );
            break;
        case TlsStreamItemSemanticKind::none:
        default:
            break;
        }
    }
    return disposition;
}

bool selected_packet_completes_record(const TlsSelectedPacketRecordContext& context) {
    return context.selected_contribution_flow_packet_index.has_value() &&
        context.completion_flow_packet_index.has_value() &&
        *context.selected_contribution_flow_packet_index == *context.completion_flow_packet_index;
}

const TlsSelectedPacketContribution* find_selected_packet_contribution(
    const TlsSelectedPacketRecordContext& context,
    const std::uint64_t flow_packet_index
) {
    const auto it = std::find_if(
        context.contributions.begin(),
        context.contributions.end(),
        [&](const TlsSelectedPacketContribution& contribution) {
            return contribution.flow_packet_index == flow_packet_index;
        }
    );
    return it == context.contributions.end() ? nullptr : &(*it);
}

bool selected_packet_starts_record(
    const TlsSelectedPacketRecordContext& context,
    const std::uint64_t flow_packet_index
) {
    return !context.contributions.empty() &&
        context.contributions.front().flow_packet_index == flow_packet_index;
}

TransportPayloadDisposition inspect_tls_payload_ownership(
    std::span<const std::uint8_t> transport_payload_bytes,
    const TlsInspectionParserContext& initial_parser_context
) {
    return classify_tls_records_ownership(inspect_tls_summary_records(
        transport_payload_bytes,
        initial_parser_context,
        false,
        false
    ));
}

TransportPayloadDisposition detect_selected_packet_tls_ownership(
    const PacketSummaryOptions& options
) {
    auto disposition = classify_reconstructed_tls_ownership(options.reconstructed_tls_records);
    const auto reassembled_prefix_bytes = selected_packet_reassembled_tls_prefix_bytes(options);
    if (reassembled_prefix_bytes == 0U) {
        return strongest_transport_payload_disposition(
            disposition,
            inspect_tls_payload_ownership(
                options.transport_payload_bytes,
                selected_packet_starting_tls_initial_context(options)
            )
        );
    }

    auto tls_initial_parser_context = options.tls_initial_parser_context;
    const auto flow_packet_index = options.flow_packet_index;
    if (flow_packet_index.has_value()) {
        for (const auto& reconstructed_record : options.reconstructed_tls_records) {
            const auto* selected_contribution =
                find_selected_packet_contribution(reconstructed_record, *flow_packet_index);
            if (selected_contribution == nullptr || selected_packet_starts_record(reconstructed_record, *flow_packet_index)) {
                continue;
            }
            tls_initial_parser_context = advance_tls_summary_parser_context(
                tls_initial_parser_context,
                reconstructed_record
            );
        }
    }

    const auto remaining_tls_payload =
        reassembled_prefix_bytes < options.transport_payload_bytes.size()
            ? options.transport_payload_bytes.subspan(reassembled_prefix_bytes)
            : std::span<const std::uint8_t> {};
    return strongest_transport_payload_disposition(
        disposition,
        inspect_tls_payload_ownership(remaining_tls_payload, tls_initial_parser_context)
    );
}

TransportPayloadDisposition detect_supported_transport_payload_ownership(
    std::span<const std::uint8_t> packet_bytes,
    const std::uint32_t data_link_type,
    const PacketDetails& details,
    const PacketSummaryOptions& options
) {
    if (options.quic_presentation.has_value()) {
        const auto quic_disposition = classify_quic_payload_ownership(*options.quic_presentation);
        if (quic_disposition != TransportPayloadDisposition::none) {
            return quic_disposition;
        }
    }

    const auto tls_disposition = detect_selected_packet_tls_ownership(options);
    if (tls_disposition != TransportPayloadDisposition::none) {
        return tls_disposition;
    }

    if (details.has_udp) {
        if (options.dns_summary_presentation_kind.has_value() &&
            details.dns_message.has_value() &&
            details.dns_message->status != DnsInspectionStatus::not_enough_header) {
            return TransportPayloadDisposition::claimed_by_supported_protocol;
        }
        DnsPacketProtocolAnalyzer dns_analyzer {};
        if (dns_analyzer.analyze(packet_bytes, data_link_type).has_value()) {
            return TransportPayloadDisposition::claimed_by_supported_protocol;
        }
    }
    if (details.has_tcp) {
        HttpPacketProtocolAnalyzer http_analyzer {};
        if (http_analyzer.analyze(packet_bytes, data_link_type).has_value()) {
            return TransportPayloadDisposition::claimed_by_supported_protocol;
        }
    }

    return TransportPayloadDisposition::none;
}

std::vector<PacketSummaryLayer> build_prepared_selected_packet_tls_layers(
    const PacketSummaryOptions& options
) {
    std::vector<PacketSummaryLayer> layers {};
    if (options.quic_presentation.has_value()) {
        return layers;
    }

    const auto append_reconstructed_tls_record_summary =
        [&](const TlsSelectedPacketRecordContext& reconstructed_record) {
            layers.push_back(build_tls_reassembled_metadata_layer(reconstructed_record));
            if (reconstructed_record.status == TlsSelectedPacketStatus::complete &&
                selected_packet_completes_record(reconstructed_record) &&
                reconstructed_record.captured_bytes.size() == reconstructed_record.total_record_size) {
                const auto reconstructed_tls_layers = build_tls_summary_layers(
                    std::span<const std::uint8_t>(
                        reconstructed_record.captured_bytes.data(),
                        reconstructed_record.captured_bytes.size()
                    ),
                    reconstructed_record.initial_parser_context
                );
                layers.insert(
                    layers.end(),
                    reconstructed_tls_layers.begin(),
                    reconstructed_tls_layers.end()
                );
            }
        };

    const auto reassembled_prefix_bytes = selected_packet_reassembled_tls_prefix_bytes(options);
    if (reassembled_prefix_bytes == 0U) {
        const auto tls_layers = build_tls_summary_layers(
            options.transport_payload_bytes,
            selected_packet_starting_tls_initial_context(options)
        );
        layers.insert(layers.end(), tls_layers.begin(), tls_layers.end());
        for (const auto& reconstructed_record : options.reconstructed_tls_records) {
            append_reconstructed_tls_record_summary(reconstructed_record);
        }
        return layers;
    }

    const auto flow_packet_index = *options.flow_packet_index;
    auto tls_initial_parser_context = options.tls_initial_parser_context;
    for (const auto& reconstructed_record : options.reconstructed_tls_records) {
        const auto* selected_contribution =
            find_selected_packet_contribution(reconstructed_record, flow_packet_index);
        if (selected_contribution == nullptr || selected_packet_starts_record(reconstructed_record, flow_packet_index)) {
            continue;
        }
        append_reconstructed_tls_record_summary(reconstructed_record);
        tls_initial_parser_context = advance_tls_summary_parser_context(
            tls_initial_parser_context,
            reconstructed_record
        );
    }

    const auto remaining_tls_payload =
        reassembled_prefix_bytes < options.transport_payload_bytes.size()
            ? options.transport_payload_bytes.subspan(reassembled_prefix_bytes)
            : std::span<const std::uint8_t> {};
    const auto tls_layers = build_tls_summary_layers(
        remaining_tls_payload,
        tls_initial_parser_context
    );
    layers.insert(layers.end(), tls_layers.begin(), tls_layers.end());

    for (const auto& reconstructed_record : options.reconstructed_tls_records) {
        const auto* selected_contribution =
            find_selected_packet_contribution(reconstructed_record, flow_packet_index);
        if (selected_contribution == nullptr || !selected_packet_starts_record(reconstructed_record, flow_packet_index)) {
            continue;
        }
        append_reconstructed_tls_record_summary(reconstructed_record);
    }

    return layers;
}

}  // namespace

PacketSummaryOptions SelectedPacketSummaryPreparation::make_options() const {
    PacketSummaryOptions options {};
    options.flow_packet_index = flow_packet_index;
    options.transport_payload_length = transport_payload_length;
    options.original_transport_payload_length = original_transport_payload_length;
    options.transport_payload_bytes = std::span<const std::uint8_t>(transport_payload.data(), transport_payload.size());
    options.checksum_summary_lines = checksum_summary_lines;
    options.checksum_warning_lines = checksum_warning_lines;
    options.packet_data_preview_bytes = std::span<const std::uint8_t>(packet_data_preview.data(), packet_data_preview.size());
    options.tls_initial_parser_context = tls_initial_parser_context;
    options.reconstructed_tls_records = reconstructed_tls_records;
    options.tls_summary_layers = tls_summary_layers;
    options.quic_presentation = quic_presentation;
    options.dns_summary_presentation_kind = dns_summary_presentation_kind;
    options.packet_data = packet_data;
    return options;
}

SelectedPacketSummaryPreparation prepare_selected_packet_summary(
    CaptureSession& session,
    const PacketDetails& details,
    const PacketRef& packet,
    const std::optional<std::size_t> flow_index,
    const std::optional<std::uint64_t> flow_packet_index,
    const std::optional<std::size_t> loaded_packet_window_count,
    const std::optional<std::uint32_t> transport_payload_length,
    const std::optional<std::uint32_t> original_transport_payload_length,
    std::vector<std::string> checksum_summary_lines,
    std::vector<std::string> checksum_warning_lines
) {
    const auto packet_bytes = session.read_packet_data(packet);
    PacketPayloadService payload_service {};
    auto transport_payload = payload_service.extract_transport_payload(packet_bytes, packet.data_link_type);

    auto tls_packet_analysis =
        flow_index.has_value() &&
        flow_packet_index.has_value() &&
        loaded_packet_window_count.has_value()
            ? analyze_selected_packet_tls_contexts(
                session,
                *flow_index,
                *flow_packet_index,
                *loaded_packet_window_count
            )
            : TlsSelectedPacketAnalysis {
                .initial_parser_context = TlsInspectionParserContext {
                    .semantic_state = TlsInspectionSemanticState::plaintext,
                },
            };

    auto quic_presentation =
        flow_index.has_value()
            ? session.derive_quic_presentation_for_packet(*flow_index, packet.packet_index)
            : std::optional<QuicPresentationResult> {};

    SelectedPacketSummaryPreparation preparation {
        .flow_packet_index = flow_packet_index,
        .transport_payload_length = transport_payload_length,
        .original_transport_payload_length = original_transport_payload_length,
        .transport_payload = std::move(transport_payload),
        .checksum_summary_lines = std::move(checksum_summary_lines),
        .checksum_warning_lines = std::move(checksum_warning_lines),
        .packet_data_preview = {},
        .tls_initial_parser_context = tls_packet_analysis.initial_parser_context,
        .reconstructed_tls_records = std::move(tls_packet_analysis.reconstructed_records),
        .tls_summary_layers = {},
        .quic_presentation = std::move(quic_presentation),
        .dns_summary_presentation_kind = resolve_dns_summary_presentation_kind(session, details, flow_index),
        .packet_data = std::nullopt,
    };

    const auto assign_packet_data_preview_from_packet_offset =
        [&](const std::uint32_t packet_offset, const std::uint32_t captured_length) {
            preparation.packet_data_preview.clear();
            if (captured_length == 0U || packet_offset >= packet_bytes.size()) {
                return;
            }

            const auto preview_length = std::min<std::size_t>({
                static_cast<std::size_t>(captured_length),
                packet_bytes.size() - static_cast<std::size_t>(packet_offset),
                32U,
            });
            if (preview_length == 0U) {
                return;
            }

            preparation.packet_data_preview.assign(
                packet_bytes.begin() + static_cast<std::ptrdiff_t>(packet_offset),
                packet_bytes.begin() + static_cast<std::ptrdiff_t>(packet_offset + preview_length)
            );
        };

    const auto classify_packet_data_disposition =
        [&](const PacketDataPresentation& packet_data, const bool transport_truncated) {
            if (packet_data.captured_length == 0U) {
                return TransportPayloadDisposition::none;
            }
            if (packet.is_ip_fragmented) {
                return TransportPayloadDisposition::none;
            }
            if (transport_truncated ||
                packet_data.captured_length != packet_data.declared_length) {
                return TransportPayloadDisposition::unavailable_or_truncated;
            }

            const auto disposition = detect_supported_transport_payload_ownership(
                std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
                packet.data_link_type,
                details,
                preparation.make_options()
            );
            return disposition == TransportPayloadDisposition::none
                ? TransportPayloadDisposition::unclaimed_data
                : disposition;
        };

    if (details.effective_transport_payload.has_value()) {
        const auto& effective_payload = *details.effective_transport_payload;
        PacketDataPresentation packet_data {};
        packet_data.role = PacketDataRole::transport_payload;
        packet_data.transport = effective_payload.transport == EffectiveTransportKind::tcp
            ? PacketDataTransportKind::tcp
            : (effective_payload.transport == EffectiveTransportKind::udp
                ? PacketDataTransportKind::udp
                : PacketDataTransportKind::unknown);
        packet_data.placement =
            effective_payload.summary_placement == EffectiveTransportSummaryPlacement::after_tcp
                ? PacketDataPlacement::after_tcp
                : effective_payload.summary_placement == EffectiveTransportSummaryPlacement::after_udp
                    ? PacketDataPlacement::after_udp
                    : effective_payload.summary_placement == EffectiveTransportSummaryPlacement::after_inner_tcp
                        ? PacketDataPlacement::after_inner_tcp
                        : effective_payload.summary_placement == EffectiveTransportSummaryPlacement::after_inner_udp
                            ? PacketDataPlacement::after_inner_udp
                            : PacketDataPlacement::none;
        packet_data.captured_length = effective_payload.captured_payload_length;
        packet_data.declared_length = effective_payload.declared_payload_length.value_or(packet_data.captured_length);
        packet_data.declared_length_reliable = effective_payload.declared_payload_length.has_value();
        packet_data.truncation_reliable = effective_payload.declared_payload_length.has_value();
        assign_packet_data_preview_from_packet_offset(
            effective_payload.payload_offset,
            packet_data.captured_length
        );

        const bool outer_transport_truncated =
            transport_payload_length.has_value() &&
            original_transport_payload_length.has_value() &&
            *transport_payload_length < *original_transport_payload_length;
        const bool effective_transport_truncated =
            effective_payload.payload_truncated ||
            (effective_payload.role == EffectiveTransportRole::top_level &&
             outer_transport_truncated);
        if (effective_transport_truncated && !packet_data.truncation_reliable) {
            packet_data.disposition = TransportPayloadDisposition::unavailable_or_truncated;
        } else {
            packet_data.disposition = classify_packet_data_disposition(
                packet_data,
                effective_transport_truncated
            );
        }
        preparation.packet_data = packet_data;
    }

    preparation.tls_summary_layers = build_prepared_selected_packet_tls_layers(preparation.make_options());
    return preparation;
}

std::vector<TlsRecordModel> inspect_tls_summary_records(
    std::span<const std::uint8_t> transport_payload_bytes,
    const TlsInspectionParserContext& initial_parser_context,
    const bool force_encrypted_handshake_records,
    const bool force_encrypted_alert_records
) {
    if (!tls_summary_payload_is_owned_by_tls(transport_payload_bytes, initial_parser_context)) {
        return {};
    }

    TlsInspectionParser parser {};
    auto inspection = parser.inspect(transport_payload_bytes, initial_parser_context);
    if (force_encrypted_handshake_records) {
        for (auto& record : inspection.records) {
            if (record.status != TlsRecordStatus::complete ||
                record.content_type_kind != TlsRecordContentTypeKind::handshake) {
                continue;
            }

            record.handshake_payload_kind = TlsHandshakePayloadKind::encrypted_opaque;
            record.handshake_messages.clear();
        }
    }
    if (force_encrypted_alert_records) {
        for (auto& record : inspection.records) {
            if (record.status != TlsRecordStatus::complete ||
                record.content_type_kind != TlsRecordContentTypeKind::alert) {
                continue;
            }

            record.alert_payload_kind = TlsAlertPayloadKind::encrypted_opaque;
            record.alert_parse_status = TlsAlertParseStatus::not_attempted;
            record.alert_entries.clear();
        }
    }

    return inspection.records;
}

TlsInspectionParserContext advance_tls_summary_parser_context(
    const TlsInspectionParserContext& current_context,
    const TlsSelectedPacketRecordContext& reconstructed_record
) {
    const bool selected_packet_completes_reconstructed_record =
        reconstructed_record.selected_contribution_flow_packet_index.has_value() &&
        reconstructed_record.completion_flow_packet_index.has_value() &&
        *reconstructed_record.selected_contribution_flow_packet_index ==
            *reconstructed_record.completion_flow_packet_index;
    if ((reconstructed_record.semantic_kind == TlsStreamItemSemanticKind::change_cipher_spec ||
         reconstructed_record.semantic_kind == TlsStreamItemSemanticKind::plaintext_handshake ||
         reconstructed_record.semantic_kind == TlsStreamItemSemanticKind::generic_record) &&
        reconstructed_record.status == TlsSelectedPacketStatus::complete &&
        reconstructed_record.captured_bytes.size() == reconstructed_record.total_record_size &&
        selected_packet_completes_reconstructed_record) {
        TlsInspectionParser parser {};
        return parser.inspect(
            std::span<const std::uint8_t>(
                reconstructed_record.captured_bytes.data(),
                reconstructed_record.captured_bytes.size()
            ),
            reconstructed_record.initial_parser_context
        ).final_context;
    }
    return current_context;
}

TlsInspectionParserContext selected_packet_starting_tls_initial_context(
    const PacketSummaryOptions& options
) {
    if (!options.flow_packet_index.has_value()) {
        return options.tls_initial_parser_context;
    }

    if (options.tls_initial_parser_context.semantic_state != TlsInspectionSemanticState::unknown) {
        return options.tls_initial_parser_context;
    }

    const auto flow_packet_index = *options.flow_packet_index;
    for (const auto& reconstructed_record : options.reconstructed_tls_records) {
        if (selected_packet_starts_record(reconstructed_record, flow_packet_index)) {
            return reconstructed_record.initial_parser_context;
        }
    }

    return options.tls_initial_parser_context;
}

std::size_t selected_packet_reassembled_tls_prefix_bytes(const PacketSummaryOptions& options) {
    if (!options.flow_packet_index.has_value()) {
        return 0U;
    }

    std::size_t consumed_prefix_bytes = 0U;
    const auto flow_packet_index = *options.flow_packet_index;
    for (const auto& reconstructed_record : options.reconstructed_tls_records) {
        const auto* selected_contribution =
            find_selected_packet_contribution(reconstructed_record, flow_packet_index);
        if (selected_contribution == nullptr) {
            continue;
        }
        if (selected_packet_starts_record(reconstructed_record, flow_packet_index)) {
            break;
        }
        consumed_prefix_bytes += selected_contribution->captured_byte_count;
    }

    return std::min(consumed_prefix_bytes, options.transport_payload_bytes.size());
}

}  // namespace pfl::session_detail
