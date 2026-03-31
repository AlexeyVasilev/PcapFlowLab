#include "core/services/CaptureImportProcessor.h"

#include <span>
#include <system_error>

#include "../../../core/open_context.h"
#include "core/index/CaptureIndex.h"
#include "core/io/LinkType.h"
#include "core/services/PacketIngestor.h"

namespace pfl {

namespace {

constexpr std::uint64_t kOpenProgressReportPacketInterval = 1000U;

void report_open_progress(OpenContext* ctx) {
    if (ctx != nullptr && ctx->on_progress) {
        ctx->on_progress(ctx->progress);
    }
}

[[nodiscard]] bool should_cancel(const OpenContext* ctx) noexcept {
    return ctx != nullptr && ctx->is_cancel_requested();
}

[[nodiscard]] bool is_safe_partial_import(const CaptureState& state, const OpenContext* ctx) noexcept {
    return !should_cancel(ctx) && state.summary.packet_count > 0U;
}

template <typename Reader>
void capture_reader_failure(OpenContext* ctx, const Reader& reader) {
    if (ctx != nullptr && reader.last_error().has_details()) {
        ctx->set_failure(reader.last_error());
    }
}

template <typename Reader>
CaptureImportResult import_packets(Reader& reader, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx) {
    while (const auto packet = reader.read_next()) {
        if (should_cancel(ctx)) {
            report_open_progress(ctx);
            return CaptureImportResult::failure;
        }

        if (ctx != nullptr) {
            ++ctx->progress.packets_processed;
            ctx->progress.bytes_processed += static_cast<std::uint64_t>(packet->bytes.size());

            if (ctx->on_progress && (ctx->progress.packets_processed % kOpenProgressReportPacketInterval) == 0U) {
                ctx->on_progress(ctx->progress);
            }
        }

        processor.process_packet(*packet, state);

        if (should_cancel(ctx)) {
            report_open_progress(ctx);
            return CaptureImportResult::failure;
        }
    }

    if (ctx != nullptr && ctx->on_progress &&
        (ctx->progress.packets_processed > 0U || ctx->progress.bytes_processed > 0U || ctx->progress.has_total())) {
        ctx->on_progress(ctx->progress);
    }

    if (should_cancel(ctx)) {
        return CaptureImportResult::failure;
    }

    if (reader.has_error()) {
        capture_reader_failure(ctx, reader);
        return is_safe_partial_import(state, ctx)
            ? CaptureImportResult::partial_success_with_warning
            : CaptureImportResult::failure;
    }

    return CaptureImportResult::success;
}

}  // namespace

CaptureImportProcessor::CaptureImportProcessor(const AnalysisSettings settings)
    : hint_service_(settings) {
}

void CaptureImportProcessor::process_packet(const RawPcapPacket& packet, CaptureState& state) const {
    PacketIngestor ingestor {state};

    const auto decoded = decoder_.decode(packet);
    const auto packet_bytes = std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size());

    if (decoded.ipv4.has_value()) {
        ingestor.ingest(*decoded.ipv4);
        auto& connection = state.ipv4_connections.get_or_create(make_connection_key(decoded.ipv4->flow_key));
        if (!decoded.ipv4->packet_ref.is_ip_fragmented) {
            connection.apply_hints(hint_service_.detect(packet_bytes, packet.data_link_type, decoded.ipv4->flow_key));
        }
        return;
    }

    if (decoded.ipv6.has_value()) {
        ingestor.ingest(*decoded.ipv6);
        auto& connection = state.ipv6_connections.get_or_create(make_connection_key(decoded.ipv6->flow_key));
        if (!decoded.ipv6->packet_ref.is_ip_fragmented) {
            connection.apply_hints(hint_service_.detect(packet_bytes, packet.data_link_type, decoded.ipv6->flow_key));
        }
    }
}

CaptureImportResult import_capture_from_reader(PcapReader& reader, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx) {
    if (!is_supported_capture_link_type(reader.data_link_type())) {
        if (ctx != nullptr) {
            OpenFailureInfo failure {};
            failure.reason = "unsupported capture link type";
            ctx->set_failure(std::move(failure));
        }
        return CaptureImportResult::failure;
    }

    return import_packets(reader, state, processor, ctx);
}

CaptureImportResult import_capture_from_reader(PcapNgReader& reader, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx) {
    return import_packets(reader, state, processor, ctx);
}

CaptureImportResult import_capture_from_path(const std::filesystem::path& path, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx) {
    if (ctx != nullptr) {
        ctx->progress = {};
        ctx->clear_failure();
        std::error_code error {};
        const auto size = std::filesystem::file_size(path, error);
        if (!error) {
            ctx->progress.total_bytes = static_cast<std::uint64_t>(size);
        }
    }

    if (should_cancel(ctx)) {
        report_open_progress(ctx);
        return CaptureImportResult::failure;
    }

    switch (detect_capture_source_format(path)) {
    case CaptureSourceFormat::classic_pcap: {
        PcapReader reader {};
        if (!reader.open(path)) {
            capture_reader_failure(ctx, reader);
            return CaptureImportResult::failure;
        }

        return import_capture_from_reader(reader, state, processor, ctx);
    }
    case CaptureSourceFormat::pcapng: {
        PcapNgReader reader {};
        if (!reader.open(path)) {
            capture_reader_failure(ctx, reader);
            return CaptureImportResult::failure;
        }

        return import_capture_from_reader(reader, state, processor, ctx);
    }
    default:
        if (ctx != nullptr) {
            OpenFailureInfo failure {};
            std::error_code exists_error {};
            if (!std::filesystem::exists(path, exists_error) || exists_error) {
                failure.reason = "file access failed";
            } else {
                failure.reason = "unsupported or unreadable capture format";
            }
            ctx->set_failure(std::move(failure));
        }
        return CaptureImportResult::failure;
    }
}

}  // namespace pfl
