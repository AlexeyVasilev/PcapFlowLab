#include "core/services/CaptureImportProcessor.h"

#include <algorithm>
#include <exception>
#include <system_error>
#include <vector>

#include "../../../core/open_context.h"
#include "core/index/CaptureIndex.h"
#include "core/io/LinkType.h"
#include "core/services/CaptureImportApplication.h"
#include "core/services/CaptureImportPrefixPolicy.h"

namespace pfl {

namespace {

constexpr std::uint64_t kOpenProgressReportPacketInterval = 1000U;

[[nodiscard]] const dissection::DissectionRegistry& require_common_direct_import_registry() {
    static const auto built = dissection::make_common_direct_registry();
    if (!built.ok() || !built.registry.has_value()) {
        std::terminate();
    }

    return *built.registry;
}

void report_open_progress(OpenContext* ctx) {
    if (ctx != nullptr && ctx->on_progress) {
        ctx->on_progress(ctx->progress);
    }
}

[[nodiscard]] bool should_cancel(const OpenContext* ctx) noexcept {
    return ctx != nullptr && ctx->is_cancel_requested();
}

[[nodiscard]] bool is_safe_partial_import(const CaptureState& state, const OpenContext* ctx) noexcept {
    return !should_cancel(ctx) && (state.summary.packet_count > 0U || !state.unrecognized_packets.empty());
}

void release_large_import_packet_capacity(RawPcapPacket& packet) {
    if (packet.bytes.capacity() < kMinCapturedLengthForStagedImportBytes) {
        return;
    }

    // Keep import-only small-packet reuse from pinning a large staged packet buffer
    // for the rest of the capture open.
    std::vector<std::uint8_t> {}.swap(packet.bytes);
}

template <typename Reader>
void capture_reader_failure(OpenContext* ctx, const Reader& reader) {
    if (ctx != nullptr && reader.last_error().has_details()) {
        ctx->set_failure(reader.last_error());
    }
}

CaptureImportResult import_classic_packets(PcapReader& reader,
                                           CaptureState& state,
                                           const CaptureImportProcessor& processor,
                                           OpenContext* ctx) {
    auto adaptive_header_prefix_bytes = kInitialImportHeaderPrefixBytes;
    RawPcapPacket reusable_packet {};

    while (reader.read_next_import_packet_into(
        reusable_packet,
            adaptive_header_prefix_bytes,
            kMinCapturedLengthForStagedImportBytes
        )) {

        if (should_cancel(ctx)) {
            report_open_progress(ctx);
            return CaptureImportResult::failure;
        }

        if (ctx != nullptr) {
            ++ctx->progress.packets_processed;
            ctx->progress.bytes_processed += reusable_packet.captured_length;

            if (ctx->on_progress && (ctx->progress.packets_processed % kOpenProgressReportPacketInterval) == 0U) {
                ctx->on_progress(ctx->progress);
            }
        }

        if (!processor.process_classic_import_packet(reader, reusable_packet, state, adaptive_header_prefix_bytes)) {
            break;
        }

        release_large_import_packet_capacity(reusable_packet);

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

template <typename Reader>
CaptureImportResult import_full_packets(Reader& reader, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx) {
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
    : registry_(&require_common_direct_import_registry())
    , hint_service_(settings, true) {
}

bool CaptureImportProcessor::process_classic_import_packet(PcapReader& reader,
                                                           RawPcapPacket& packet,
                                                           CaptureState& state,
                                                           std::size_t& adaptive_header_prefix_bytes) const {
    const auto finalize_prefix_packet = [&reader, &packet]() {
        return reader.finish_prefix_packet(packet);
    };

    if (const auto required_bytes = required_classic_import_prefix_bytes(packet); required_bytes.has_value()) {
        if (!reader.materialize_packet_bytes(packet)) {
            return false;
        }

        adaptive_header_prefix_bytes =
            grow_adaptive_import_header_prefix(adaptive_header_prefix_bytes, *required_bytes);
        process_packet(packet, state);
        return true;
    }

    auto result = run_unified_import_packet(packet, *registry_);
    if (!result.decision.has_decoded_packet() && packet.bytes.size() < packet.captured_length) {
        if (!reader.materialize_packet_bytes(packet)) {
            return false;
        }

        process_packet(packet, state);
        return true;
    }

    void* materializer_context[] {&reader, &packet};
    const auto applied = apply_unified_import_packet_result(
        packet,
        result,
        state,
        hint_service_,
        PacketBytesMaterializer {
            .callback = [](void* context) {
                auto** parts = static_cast<void**>(context);
                auto* packet_reader = static_cast<PcapReader*>(parts[0]);
                auto* raw_packet = static_cast<RawPcapPacket*>(parts[1]);
                return packet_reader->materialize_packet_bytes(*raw_packet);
            },
            .context = materializer_context,
        }
    );
    if (!applied) {
        return false;
    }

    return finalize_prefix_packet();
}

void CaptureImportProcessor::process_packet(const RawPcapPacket& packet, CaptureState& state) const {
    auto packet_copy = packet;
    static_cast<void>(process_packet_with_unified_dissection(
        packet_copy,
        state,
        *registry_,
        hint_service_
    ));
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

    return import_classic_packets(reader, state, processor, ctx);
}

CaptureImportResult import_capture_from_reader(PcapNgReader& reader, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx) {
    return import_full_packets(reader, state, processor, ctx);
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



