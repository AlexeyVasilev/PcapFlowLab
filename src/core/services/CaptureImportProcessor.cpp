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

template <typename Reader>
bool import_packets(Reader& reader, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx) {
    while (const auto packet = reader.read_next()) {
        if (ctx != nullptr) {
            ++ctx->progress.packets_processed;
            ctx->progress.bytes_processed += static_cast<std::uint64_t>(packet->bytes.size());

            if (ctx->on_progress && (ctx->progress.packets_processed % kOpenProgressReportPacketInterval) == 0U) {
                ctx->on_progress(ctx->progress);
            }
        }

        processor.process_packet(*packet, state);
    }

    if (ctx != nullptr && ctx->on_progress &&
        (ctx->progress.packets_processed > 0U || ctx->progress.bytes_processed > 0U || ctx->progress.has_total())) {
        ctx->on_progress(ctx->progress);
    }

    return !reader.has_error();
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

bool import_capture_from_reader(PcapReader& reader, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx) {
    if (!is_supported_capture_link_type(reader.data_link_type())) {
        return false;
    }

    return import_packets(reader, state, processor, ctx);
}

bool import_capture_from_reader(PcapNgReader& reader, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx) {
    return import_packets(reader, state, processor, ctx);
}

bool import_capture_from_path(const std::filesystem::path& path, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx) {
    if (ctx != nullptr) {
        ctx->progress = {};
        std::error_code error {};
        const auto size = std::filesystem::file_size(path, error);
        if (!error) {
            ctx->progress.total_bytes = static_cast<std::uint64_t>(size);
        }
    }

    switch (detect_capture_source_format(path)) {
    case CaptureSourceFormat::classic_pcap: {
        PcapReader reader {};
        if (!reader.open(path)) {
            return false;
        }

        return import_capture_from_reader(reader, state, processor, ctx);
    }
    case CaptureSourceFormat::pcapng: {
        PcapNgReader reader {};
        if (!reader.open(path)) {
            return false;
        }

        return import_capture_from_reader(reader, state, processor, ctx);
    }
    default:
        return false;
    }
}

}  // namespace pfl



