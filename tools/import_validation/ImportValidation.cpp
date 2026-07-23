#include "tools/import_validation/ImportValidation.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <optional>
#include <sstream>
#include <system_error>
#include <string_view>
#include <utility>

#include "core/dissection/CommonDirectDissection.h"
#include "core/dissection/DissectionEngine.h"
#include "core/dissection/PacketSlice.h"
#include "core/index/CaptureIndex.h"
#include "core/io/PcapNgReader.h"
#include "core/io/PcapReader.h"
#include "core/services/CaptureImportApplication.h"
#include "core/services/CaptureImportPrefixPolicy.h"
#include "core/services/CaptureImportProcessor.h"
#include "core/services/DissectionImportAdapter.h"
#include "core/services/FlowHintService.h"
#include "core/services/PacketIngestor.h"

#if defined(_WIN32)
#include <windows.h>
#include <psapi.h>
#elif defined(__linux__)
#include <sys/resource.h>
#endif

namespace pfl {

namespace {

using Clock = std::chrono::steady_clock;

struct PeakMemoryReader {
    [[nodiscard]] std::optional<std::uint64_t> read() const noexcept {
#if defined(_WIN32)
        PROCESS_MEMORY_COUNTERS counters {};
        if (!GetProcessMemoryInfo(GetCurrentProcess(), &counters, sizeof(counters))) {
            return std::nullopt;
        }
        return static_cast<std::uint64_t>(counters.PeakWorkingSetSize);
#elif defined(__linux__)
        rusage usage {};
        if (getrusage(RUSAGE_SELF, &usage) != 0) {
            return std::nullopt;
        }
        return static_cast<std::uint64_t>(usage.ru_maxrss) * 1024ULL;
#else
        return std::nullopt;
#endif
    }
};

struct LegacyImportLoopMetrics {
    std::uint64_t packets_processed {0U};
    std::uint64_t captured_bytes {0U};
};

struct ImportExecution {
    bool success {false};
    std::string error_text {};
    CaptureState state {};
    LegacyImportLoopMetrics loop_metrics {};
};

struct MismatchRecorder {
    std::size_t limit {32U};
    std::size_t total_count {0U};
    std::vector<ImportValidationMismatch> mismatches {};

    void record(
        const ImportValidationMismatchCategory category,
        std::string entity,
        std::string field,
        std::string legacy_value,
        std::string unified_value
    ) {
        ++total_count;
        if (mismatches.size() >= limit) {
            return;
        }

        mismatches.push_back(ImportValidationMismatch {
            .category = category,
            .entity = std::move(entity),
            .field = std::move(field),
            .legacy_value = std::move(legacy_value),
            .unified_value = std::move(unified_value),
        });
    }
};

[[nodiscard]] std::string format_registry_build_failure(
    const dissection::DissectionRegistryBuildResult& result
) {
    switch (result.status) {
    case dissection::DissectionRegistryBuildStatus::success:
        return "common direct registry build failed without details";
    case dissection::DissectionRegistryBuildStatus::duplicate_selector: {
        std::ostringstream builder {};
        builder << "common direct registry build failed: duplicate selector";
        if (result.conflicting_registration_index.has_value()) {
            builder << " at registration index " << *result.conflicting_registration_index;
        }
        if (result.conflicting_selector.has_value()) {
            builder << " (domain="
                    << static_cast<unsigned int>(result.conflicting_selector->domain)
                    << ", value=" << result.conflicting_selector->value << ')';
        }
        return builder.str();
    }
    case dissection::DissectionRegistryBuildStatus::null_dissector:
        if (result.conflicting_registration_index.has_value()) {
            return "common direct registry build failed: null dissector at registration index " +
                std::to_string(*result.conflicting_registration_index);
        }
        return "common direct registry build failed: null dissector";
    }

    return "common direct registry build failed with unknown status";
}

[[nodiscard]] dissection::PacketSlice make_root_slice(const RawPcapPacket& packet) {
    return dissection::make_root_packet_slice(
        dissection::ByteSourceId::captured_frame(static_cast<std::uint32_t>(packet.packet_index)),
        packet.bytes,
        packet.captured_length,
        packet.original_length
    );
}

[[nodiscard]] dissection::ImportDissectionFacts run_unified_shadow_import(
    const RawPcapPacket& packet,
    const dissection::DissectionRegistry& registry
) {
    dissection::ImportDissectionCollector collector {};
    const dissection::DissectionEngine engine {};
    const auto result = engine.run(
        registry,
        dissection::make_link_type_selector(packet.data_link_type),
        make_root_slice(packet),
        collector.consumer()
    );
    collector.finish(result);
    return collector.facts();
}

[[nodiscard]] std::string format_protocol_path_or_empty(const ProtocolPath& path) {
    if (path.empty()) {
        return {};
    }
    return format_protocol_path(path);
}

[[nodiscard]] std::string format_packet_ref(const PacketRef& packet) {
    std::ostringstream builder {};
    builder
        << "{index=" << packet.packet_index
        << ", offset=" << packet.byte_offset
        << ", dlt=" << packet.data_link_type
        << ", caplen=" << packet.captured_length
        << ", origlen=" << packet.original_length
        << ", ts=" << packet.ts_sec << '.' << packet.ts_usec
        << ", payload=" << packet.payload_length
        << ", tcp_flags=" << static_cast<unsigned int>(packet.tcp_flags)
        << ", fragmented=" << (packet.is_ip_fragmented ? "true" : "false")
        << '}';
    return builder.str();
}

[[nodiscard]] std::string format_flow_key(const FlowKeyV4& key, const ProtocolPath& path) {
    std::ostringstream builder {};
    builder
        << "{src=" << key.src_addr << ':' << key.src_port
        << ", dst=" << key.dst_addr << ':' << key.dst_port
        << ", protocol=" << static_cast<int>(key.protocol)
        << ", path=\"" << format_protocol_path_or_empty(path) << "\"}";
    return builder.str();
}

[[nodiscard]] std::string format_flow_key(const FlowKeyV6& key, const ProtocolPath& path) {
    std::ostringstream builder {};
    builder
        << "{src_port=" << key.src_port
        << ", dst_port=" << key.dst_port
        << ", protocol=" << static_cast<int>(key.protocol)
        << ", path=\"" << format_protocol_path_or_empty(path) << "\"}";
    return builder.str();
}

[[nodiscard]] std::string format_connection_key(const ConnectionKeyV4& key, const ProtocolPath& path) {
    std::ostringstream builder {};
    builder
        << "{first=" << key.first.addr << ':' << key.first.port
        << ", second=" << key.second.addr << ':' << key.second.port
        << ", protocol=" << static_cast<int>(key.protocol)
        << ", path=\"" << format_protocol_path_or_empty(path) << "\"}";
    return builder.str();
}

[[nodiscard]] std::string format_connection_key(const ConnectionKeyV6& key, const ProtocolPath& path) {
    std::ostringstream builder {};
    builder
        << "{first_port=" << key.first.port
        << ", second_port=" << key.second.port
        << ", protocol=" << static_cast<int>(key.protocol)
        << ", path=\"" << format_protocol_path_or_empty(path) << "\"}";
    return builder.str();
}

template <typename T>
void maybe_record_scalar_mismatch(
    MismatchRecorder& recorder,
    const ImportValidationMismatchCategory category,
    const std::string& entity,
    const std::string& field,
    const T& legacy,
    const T& unified
) {
    if (legacy == unified) {
        return;
    }

    std::ostringstream legacy_builder {};
    legacy_builder << legacy;
    std::ostringstream unified_builder {};
    unified_builder << unified;
    recorder.record(category, entity, field, legacy_builder.str(), unified_builder.str());
}

[[nodiscard]] FlowKeyV4 canonical_flow_key(FlowKeyV4 key) noexcept {
    key.protocol_path_id = kInvalidProtocolPathId;
    return key;
}

[[nodiscard]] FlowKeyV6 canonical_flow_key(FlowKeyV6 key) noexcept {
    key.protocol_path_id = kInvalidProtocolPathId;
    return key;
}

[[nodiscard]] ConnectionKeyV4 canonical_connection_key(ConnectionKeyV4 key) noexcept {
    key.protocol_path_id = kInvalidProtocolPathId;
    return key;
}

[[nodiscard]] ConnectionKeyV6 canonical_connection_key(ConnectionKeyV6 key) noexcept {
    key.protocol_path_id = kInvalidProtocolPathId;
    return key;
}

[[nodiscard]] ImportValidationHintState make_hint_snapshot(
    const ConnectionHintSearchState& state,
    const bool include_hints
) noexcept {
    if (!include_hints) {
        return {};
    }

    return ImportValidationHintState {
        .unresolved_payload_attempt_count = state.unresolved_payload_attempt_count,
        .unresolved_payload_attempt_budget_exhausted = state.unresolved_payload_attempt_budget_exhausted,
    };
}

[[nodiscard]] ImportValidationFlowSnapshotV4 snapshot_flow(
    const FlowV4& flow,
    const ProtocolPathRegistry& registry
) {
    return ImportValidationFlowSnapshotV4 {
        .key = canonical_flow_key(flow.key),
        .protocol_path = registry.find(flow.key.protocol_path_id) != nullptr
            ? *registry.find(flow.key.protocol_path_id)
            : ProtocolPath {},
        .packets = flow.packets,
        .packet_count = flow.packet_count,
        .total_bytes = flow.total_bytes,
    };
}

[[nodiscard]] ImportValidationFlowSnapshotV6 snapshot_flow(
    const FlowV6& flow,
    const ProtocolPathRegistry& registry
) {
    return ImportValidationFlowSnapshotV6 {
        .key = canonical_flow_key(flow.key),
        .protocol_path = registry.find(flow.key.protocol_path_id) != nullptr
            ? *registry.find(flow.key.protocol_path_id)
            : ProtocolPath {},
        .packets = flow.packets,
        .packet_count = flow.packet_count,
        .total_bytes = flow.total_bytes,
    };
}

[[nodiscard]] ImportValidationConnectionSnapshotV4 snapshot_connection(
    const ConnectionV4& connection,
    const ProtocolPathRegistry& registry,
    const bool include_hints
) {
    return ImportValidationConnectionSnapshotV4 {
        .key = canonical_connection_key(connection.key),
        .protocol_path = registry.find(connection.key.protocol_path_id) != nullptr
            ? *registry.find(connection.key.protocol_path_id)
            : ProtocolPath {},
        .flow_a = connection.has_flow_a ? std::optional<ImportValidationFlowSnapshotV4> {snapshot_flow(connection.flow_a, registry)} : std::nullopt,
        .flow_b = connection.has_flow_b ? std::optional<ImportValidationFlowSnapshotV4> {snapshot_flow(connection.flow_b, registry)} : std::nullopt,
        .packet_count = connection.packet_count,
        .total_bytes = connection.total_bytes,
        .has_fragmented_packets = connection.has_fragmented_packets,
        .fragmented_packet_count = connection.fragmented_packet_count,
        .protocol_hint = include_hints ? connection.protocol_hint : FlowProtocolHint::unknown,
        .service_hint = include_hints ? connection.service_hint : std::string {},
        .quic_version = include_hints ? connection.quic_version : QuicVersionHint::unknown,
        .tls_version = include_hints ? connection.tls_version : TlsVersionHint::unknown,
        .hint_search_state = make_hint_snapshot(connection.hint_search_state, include_hints),
    };
}

[[nodiscard]] ImportValidationConnectionSnapshotV6 snapshot_connection(
    const ConnectionV6& connection,
    const ProtocolPathRegistry& registry,
    const bool include_hints
) {
    return ImportValidationConnectionSnapshotV6 {
        .key = canonical_connection_key(connection.key),
        .protocol_path = registry.find(connection.key.protocol_path_id) != nullptr
            ? *registry.find(connection.key.protocol_path_id)
            : ProtocolPath {},
        .flow_a = connection.has_flow_a ? std::optional<ImportValidationFlowSnapshotV6> {snapshot_flow(connection.flow_a, registry)} : std::nullopt,
        .flow_b = connection.has_flow_b ? std::optional<ImportValidationFlowSnapshotV6> {snapshot_flow(connection.flow_b, registry)} : std::nullopt,
        .packet_count = connection.packet_count,
        .total_bytes = connection.total_bytes,
        .has_fragmented_packets = connection.has_fragmented_packets,
        .fragmented_packet_count = connection.fragmented_packet_count,
        .protocol_hint = include_hints ? connection.protocol_hint : FlowProtocolHint::unknown,
        .service_hint = include_hints ? connection.service_hint : std::string {},
        .quic_version = include_hints ? connection.quic_version : QuicVersionHint::unknown,
        .tls_version = include_hints ? connection.tls_version : TlsVersionHint::unknown,
        .hint_search_state = make_hint_snapshot(connection.hint_search_state, include_hints),
    };
}

template <typename Reader>
bool legacy_import_reader_loop(
    Reader& reader,
    CaptureState& state,
    const CaptureImportProcessor& processor,
    LegacyImportLoopMetrics& metrics,
    const std::optional<std::uint64_t> max_packets
) {
    while (!max_packets.has_value() || metrics.packets_processed < *max_packets) {
        const auto packet = reader.read_next();
        if (!packet.has_value()) {
            return !reader.has_error();
        }

        processor.process_packet(*packet, state);
        ++metrics.packets_processed;
        metrics.captured_bytes += packet->captured_length;
    }

    return true;
}

bool legacy_import_classic_reader_loop(
    PcapReader& reader,
    CaptureState& state,
    const CaptureImportProcessor& processor,
    LegacyImportLoopMetrics& metrics,
    const std::optional<std::uint64_t> max_packets
) {
    std::size_t adaptive_header_prefix_bytes = kInitialImportHeaderPrefixBytes;
    RawPcapPacket packet {};

    while (!max_packets.has_value() || metrics.packets_processed < *max_packets) {
        if (!reader.read_next_import_packet_into(
                packet,
                adaptive_header_prefix_bytes,
                kMinCapturedLengthForStagedImportBytes)) {
            return !reader.has_error();
        }

        if (!processor.process_classic_import_packet(reader, packet, state, adaptive_header_prefix_bytes)) {
            return false;
        }

        ++metrics.packets_processed;
        metrics.captured_bytes += packet.captured_length;
        if (packet.bytes.capacity() >= kMinCapturedLengthForStagedImportBytes) {
            std::vector<std::uint8_t> {}.swap(packet.bytes);
        }
    }

    return true;
}

template <typename Reader>
bool unified_import_reader_loop(
    Reader& reader,
    CaptureState& state,
    const dissection::DissectionRegistry& registry,
    const FlowHintService& hint_service,
    LegacyImportLoopMetrics& metrics,
    const std::optional<std::uint64_t> max_packets
) {
    while (!max_packets.has_value() || metrics.packets_processed < *max_packets) {
        const auto packet = reader.read_next();
        if (!packet.has_value()) {
            return !reader.has_error();
        }

        auto facts = run_unified_shadow_import(*packet, registry);
        auto decision = adapt_dissection_import_facts(facts);
        if (decision.has_decoded_packet()) {
            apply_decoded_packet_import(*packet, *decision.decoded_packet, state, hint_service);
        } else {
            const auto packet_bytes = std::span<const std::uint8_t>(packet->bytes.data(), packet->bytes.size());
            apply_unrecognized_packet_import(*packet, packet_bytes, state, hint_service);
        }

        ++metrics.packets_processed;
        metrics.captured_bytes += packet->captured_length;
    }

    return true;
}

bool process_classic_unified_import_packet(
    PcapReader& reader,
    RawPcapPacket& packet,
    CaptureState& state,
    std::size_t& adaptive_header_prefix_bytes,
    const dissection::DissectionRegistry& registry,
    const FlowHintService& hint_service
) {
    auto finalize_prefix_packet = [&reader, &packet]() {
        return reader.finish_prefix_packet(packet);
    };

    if (packet.bytes.size() >= packet.captured_length) {
        auto facts = run_unified_shadow_import(packet, registry);
        auto decision = adapt_dissection_import_facts(facts);
        if (decision.has_decoded_packet()) {
            apply_decoded_packet_import(packet, *decision.decoded_packet, state, hint_service);
        } else {
            const auto packet_bytes = std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size());
            apply_unrecognized_packet_import(packet, packet_bytes, state, hint_service);
        }
        return true;
    }

    if (const auto required_bytes = required_classic_import_prefix_bytes(packet); required_bytes.has_value()) {
        if (!reader.materialize_packet_bytes(packet)) {
            return false;
        }

        adaptive_header_prefix_bytes = grow_adaptive_import_header_prefix(adaptive_header_prefix_bytes, *required_bytes);
        auto facts = run_unified_shadow_import(packet, registry);
        auto decision = adapt_dissection_import_facts(facts);
        if (decision.has_decoded_packet()) {
            apply_decoded_packet_import(packet, *decision.decoded_packet, state, hint_service);
        } else {
            const auto packet_bytes = std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size());
            apply_unrecognized_packet_import(packet, packet_bytes, state, hint_service);
        }
        return true;
    }

    PacketIngestor ingestor {state};
    auto facts = run_unified_shadow_import(packet, registry);
    auto decision = adapt_dissection_import_facts(facts);
    auto packet_bytes = std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size());

    if (decision.decoded_packet.has_value() && decision.decoded_packet->ipv4.has_value()) {
        auto& decoded = *decision.decoded_packet;
        if (const auto payload_length =
                derive_captured_transport_payload_length_from_prefix(packet, decoded.ipv4->flow_key.protocol);
            payload_length.has_value()) {
            decoded.ipv4->packet_ref.payload_length = *payload_length;
        }

        decoded.ipv4->flow_key.protocol_path_id =
            intern_protocol_path_id_for_flow_identity(state, decoded.protocol_path_builder);
        auto& connection = ingestor.ingest(*decoded.ipv4);
        if (!decoded.ipv4->packet_ref.is_ip_fragmented &&
            connection.should_attempt_hint_detection(decoded.ipv4->packet_ref, decoded.ipv4->flow_key.protocol) &&
            requires_full_packet_for_hint_detection(decoded.ipv4->packet_ref, decoded.ipv4->flow_key.protocol)) {
            if (!reader.materialize_packet_bytes(packet)) {
                return false;
            }

            packet_bytes = std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size());
            connection.apply_hints(hint_service.detect(packet_bytes, packet.data_link_type, decoded.ipv4->flow_key));
            connection.note_hint_detection_attempt(decoded.ipv4->packet_ref, decoded.ipv4->flow_key.protocol);
        } else {
            apply_import_hints_if_needed(
                packet,
                packet_bytes,
                decoded.ipv4->packet_ref,
                connection,
                decoded.ipv4->flow_key,
                hint_service);
        }
        return finalize_prefix_packet();
    }

    if (decision.decoded_packet.has_value() && decision.decoded_packet->ipv6.has_value()) {
        auto& decoded = *decision.decoded_packet;
        if (const auto payload_length =
                derive_captured_transport_payload_length_from_prefix(packet, decoded.ipv6->flow_key.protocol);
            payload_length.has_value()) {
            decoded.ipv6->packet_ref.payload_length = *payload_length;
        }

        decoded.ipv6->flow_key.protocol_path_id =
            intern_protocol_path_id_for_flow_identity(state, decoded.protocol_path_builder);
        auto& connection = ingestor.ingest(*decoded.ipv6);
        if (!decoded.ipv6->packet_ref.is_ip_fragmented &&
            connection.should_attempt_hint_detection(decoded.ipv6->packet_ref, decoded.ipv6->flow_key.protocol) &&
            requires_full_packet_for_hint_detection(decoded.ipv6->packet_ref, decoded.ipv6->flow_key.protocol)) {
            if (!reader.materialize_packet_bytes(packet)) {
                return false;
            }

            packet_bytes = std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size());
            connection.apply_hints(hint_service.detect(packet_bytes, packet.data_link_type, decoded.ipv6->flow_key));
            connection.note_hint_detection_attempt(decoded.ipv6->packet_ref, decoded.ipv6->flow_key.protocol);
        } else {
            apply_import_hints_if_needed(
                packet,
                packet_bytes,
                decoded.ipv6->packet_ref,
                connection,
                decoded.ipv6->flow_key,
                hint_service);
        }
        return finalize_prefix_packet();
    }

    if (packet.bytes.size() < packet.captured_length) {
        if (!reader.materialize_packet_bytes(packet)) {
            return false;
        }

        facts = run_unified_shadow_import(packet, registry);
        decision = adapt_dissection_import_facts(facts);
        if (decision.has_decoded_packet()) {
            apply_decoded_packet_import(packet, *decision.decoded_packet, state, hint_service);
        } else {
            packet_bytes = std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size());
            apply_unrecognized_packet_import(packet, packet_bytes, state, hint_service);
        }
        return true;
    }

    apply_unrecognized_packet_import(packet, packet_bytes, state, hint_service);
    return finalize_prefix_packet();
}

bool unified_import_classic_reader_loop(
    PcapReader& reader,
    CaptureState& state,
    const dissection::DissectionRegistry& registry,
    const FlowHintService& hint_service,
    LegacyImportLoopMetrics& metrics,
    const std::optional<std::uint64_t> max_packets
) {
    std::size_t adaptive_header_prefix_bytes = kInitialImportHeaderPrefixBytes;
    RawPcapPacket packet {};

    while (!max_packets.has_value() || metrics.packets_processed < *max_packets) {
        if (!reader.read_next_import_packet_into(
                packet,
                adaptive_header_prefix_bytes,
                kMinCapturedLengthForStagedImportBytes)) {
            return !reader.has_error();
        }

        if (!process_classic_unified_import_packet(
                reader,
                packet,
                state,
                adaptive_header_prefix_bytes,
                registry,
                hint_service)) {
            return false;
        }

        ++metrics.packets_processed;
        metrics.captured_bytes += packet.captured_length;
        if (packet.bytes.capacity() >= kMinCapturedLengthForStagedImportBytes) {
            std::vector<std::uint8_t> {}.swap(packet.bytes);
        }
    }

    return true;
}

[[nodiscard]] std::uint64_t connection_count_from_state(const CaptureState& state) noexcept {
    return state.ipv4_connections.size() + state.ipv6_connections.size();
}

[[nodiscard]] std::string reader_error_text(const PcapReader& reader) {
    return reader.last_error().reason.empty() ? std::string {"classic PCAP import failed"} : reader.last_error().reason;
}

[[nodiscard]] std::string reader_error_text(const PcapNgReader& reader) {
    return reader.last_error().reason.empty() ? std::string {"PCAPNG import failed"} : reader.last_error().reason;
}

[[nodiscard]] ImportValidationMetrics build_metrics(
    const std::filesystem::path& capture_path,
    const CaptureState& state,
    const LegacyImportLoopMetrics& loop_metrics,
    const double elapsed_seconds,
    const std::optional<std::uint64_t> peak_memory_bytes
) {
    std::error_code error {};
    const auto file_size = std::filesystem::file_size(capture_path, error);
    const auto captured_bytes = loop_metrics.captured_bytes == 0U ? state.summary.total_bytes : loop_metrics.captured_bytes;
    const auto packets_per_second = elapsed_seconds > 0.0
        ? static_cast<double>(loop_metrics.packets_processed) / elapsed_seconds
        : 0.0;
    const auto mib_per_second = elapsed_seconds > 0.0
        ? (static_cast<double>(captured_bytes) / (1024.0 * 1024.0)) / elapsed_seconds
        : 0.0;

    return ImportValidationMetrics {
        .file_size = error ? 0U : static_cast<std::uint64_t>(file_size),
        .packet_count = state.summary.packet_count,
        .captured_bytes = captured_bytes,
        .flow_count = state.summary.flow_count,
        .connection_count = connection_count_from_state(state),
        .unrecognized_count = static_cast<std::uint64_t>(state.unrecognized_packets.size()),
        .registry_size = static_cast<std::uint64_t>(state.protocol_path_registry.size()),
        .elapsed_seconds = elapsed_seconds,
        .packets_per_second = packets_per_second,
        .mib_per_second = mib_per_second,
        .peak_memory_bytes = peak_memory_bytes,
    };
}

template <typename RunnerFn>
ImportValidationRunResult run_import_mode(
    const std::filesystem::path& capture_path,
    const ImportValidationOptions& options,
    const bool measure_peak_memory,
    RunnerFn&& runner
) {
    ImportValidationRunResult result {};
    const auto start = Clock::now();
    const auto peak_reader = PeakMemoryReader {};

    auto execution = runner();
    const auto elapsed_seconds = std::chrono::duration<double>(Clock::now() - start).count();
    result.success = execution.success;
    result.error_text = std::move(execution.error_text);
    if (!result.success) {
        return result;
    }

    const auto final_peak_memory = measure_peak_memory ? peak_reader.read() : std::nullopt;
    result.metrics = build_metrics(capture_path, execution.state, execution.loop_metrics, elapsed_seconds, final_peak_memory);
    result.canonical_state = canonicalize_capture_state(execution.state, options.include_hints);
    return result;
}

[[nodiscard]] ImportExecution run_legacy_execution(
    const std::filesystem::path& capture_path,
    const ImportValidationOptions& options
) {
    ImportExecution execution {};
    const CaptureImportProcessor processor {};

    switch (detect_capture_source_format(capture_path)) {
    case CaptureSourceFormat::classic_pcap: {
        PcapReader reader {};
        if (!reader.open(capture_path)) {
            execution.error_text = reader_error_text(reader);
            return execution;
        }

        execution.success = legacy_import_classic_reader_loop(
            reader,
            execution.state,
            processor,
            execution.loop_metrics,
            options.max_packets);
        if (!execution.success) {
            execution.error_text = reader_error_text(reader);
        }
        return execution;
    }
    case CaptureSourceFormat::pcapng: {
        PcapNgReader reader {};
        if (!reader.open(capture_path)) {
            execution.error_text = reader_error_text(reader);
            return execution;
        }

        execution.success = legacy_import_reader_loop(
            reader,
            execution.state,
            processor,
            execution.loop_metrics,
            options.max_packets);
        if (!execution.success) {
            execution.error_text = reader_error_text(reader);
        }
        return execution;
    }
    default:
        execution.error_text = std::filesystem::exists(capture_path) ? "unsupported or unreadable capture format" : "file access failed";
        return execution;
    }
}

[[nodiscard]] ImportExecution run_unified_execution(
    const std::filesystem::path& capture_path,
    const ImportValidationOptions& options
) {
    ImportExecution execution {};
    const auto built = dissection::make_common_direct_registry();
    if (!built.ok() || !built.registry.has_value()) {
        execution.error_text = format_registry_build_failure(built);
        return execution;
    }

    const FlowHintService hint_service {AnalysisSettings {}, true};

    switch (detect_capture_source_format(capture_path)) {
    case CaptureSourceFormat::classic_pcap: {
        PcapReader reader {};
        if (!reader.open(capture_path)) {
            execution.error_text = reader_error_text(reader);
            return execution;
        }

        execution.success = unified_import_classic_reader_loop(
            reader,
            execution.state,
            *built.registry,
            hint_service,
            execution.loop_metrics,
            options.max_packets);
        if (!execution.success) {
            execution.error_text = reader_error_text(reader);
        }
        return execution;
    }
    case CaptureSourceFormat::pcapng: {
        PcapNgReader reader {};
        if (!reader.open(capture_path)) {
            execution.error_text = reader_error_text(reader);
            return execution;
        }

        execution.success = unified_import_reader_loop(
            reader,
            execution.state,
            *built.registry,
            hint_service,
            execution.loop_metrics,
            options.max_packets);
        if (!execution.success) {
            execution.error_text = reader_error_text(reader);
        }
        return execution;
    }
    default:
        execution.error_text = std::filesystem::exists(capture_path) ? "unsupported or unreadable capture format" : "file access failed";
        return execution;
    }
}

void compare_packet_refs(
    MismatchRecorder& recorder,
    const std::string& entity,
    const std::vector<PacketRef>& legacy,
    const std::vector<PacketRef>& unified
) {
    maybe_record_scalar_mismatch(
        recorder,
        ImportValidationMismatchCategory::packet_ref,
        entity,
        "packet_count",
        legacy.size(),
        unified.size());
    const auto shared_size = std::min(legacy.size(), unified.size());
    for (std::size_t index = 0U; index < shared_size; ++index) {
        if (legacy[index] == unified[index]) {
            continue;
        }

        recorder.record(
            ImportValidationMismatchCategory::packet_ref,
            entity + ".packet[" + std::to_string(index) + ']',
            "packet_ref",
            format_packet_ref(legacy[index]),
            format_packet_ref(unified[index]));
    }
}

void compare_flow(
    MismatchRecorder& recorder,
    const std::string& entity,
    const ImportValidationFlowSnapshotV4& legacy,
    const ImportValidationFlowSnapshotV4& unified
) {
    if (legacy.key != unified.key) {
        recorder.record(
            ImportValidationMismatchCategory::flow,
            entity,
            "key",
            format_flow_key(legacy.key, legacy.protocol_path),
            format_flow_key(unified.key, unified.protocol_path));
    }
    if (!(legacy.protocol_path == unified.protocol_path)) {
        recorder.record(
            ImportValidationMismatchCategory::flow,
            entity,
            "protocol_path",
            format_protocol_path(legacy.protocol_path),
            format_protocol_path(unified.protocol_path));
    }
    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::flow, entity, "packet_count", legacy.packet_count, unified.packet_count);
    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::flow, entity, "total_bytes", legacy.total_bytes, unified.total_bytes);
    compare_packet_refs(recorder, entity, legacy.packets, unified.packets);
}

void compare_flow(
    MismatchRecorder& recorder,
    const std::string& entity,
    const ImportValidationFlowSnapshotV6& legacy,
    const ImportValidationFlowSnapshotV6& unified
) {
    if (legacy.key != unified.key) {
        recorder.record(
            ImportValidationMismatchCategory::flow,
            entity,
            "key",
            format_flow_key(legacy.key, legacy.protocol_path),
            format_flow_key(unified.key, unified.protocol_path));
    }
    if (!(legacy.protocol_path == unified.protocol_path)) {
        recorder.record(
            ImportValidationMismatchCategory::flow,
            entity,
            "protocol_path",
            format_protocol_path(legacy.protocol_path),
            format_protocol_path(unified.protocol_path));
    }
    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::flow, entity, "packet_count", legacy.packet_count, unified.packet_count);
    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::flow, entity, "total_bytes", legacy.total_bytes, unified.total_bytes);
    compare_packet_refs(recorder, entity, legacy.packets, unified.packets);
}

void compare_connection(
    MismatchRecorder& recorder,
    const std::string& entity,
    const ImportValidationConnectionSnapshotV4& legacy,
    const ImportValidationConnectionSnapshotV4& unified,
    const bool include_hints
) {
    if (legacy.key != unified.key) {
        recorder.record(
            ImportValidationMismatchCategory::connection,
            entity,
            "key",
            format_connection_key(legacy.key, legacy.protocol_path),
            format_connection_key(unified.key, unified.protocol_path));
    }
    if (!(legacy.protocol_path == unified.protocol_path)) {
        recorder.record(
            ImportValidationMismatchCategory::connection,
            entity,
            "protocol_path",
            format_protocol_path(legacy.protocol_path),
            format_protocol_path(unified.protocol_path));
    }
    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::connection, entity, "packet_count", legacy.packet_count, unified.packet_count);
    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::connection, entity, "total_bytes", legacy.total_bytes, unified.total_bytes);
    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::connection, entity, "has_fragmented_packets", legacy.has_fragmented_packets, unified.has_fragmented_packets);
    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::connection, entity, "fragmented_packet_count", legacy.fragmented_packet_count, unified.fragmented_packet_count);

    if (include_hints) {
        maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::hint, entity, "protocol_hint", static_cast<int>(legacy.protocol_hint), static_cast<int>(unified.protocol_hint));
        maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::hint, entity, "service_hint", legacy.service_hint, unified.service_hint);
        maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::hint, entity, "quic_version", static_cast<int>(legacy.quic_version), static_cast<int>(unified.quic_version));
        maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::hint, entity, "tls_version", static_cast<int>(legacy.tls_version), static_cast<int>(unified.tls_version));
        maybe_record_scalar_mismatch(
            recorder,
            ImportValidationMismatchCategory::hint,
            entity,
            "unresolved_payload_attempt_count",
            static_cast<unsigned int>(legacy.hint_search_state.unresolved_payload_attempt_count),
            static_cast<unsigned int>(unified.hint_search_state.unresolved_payload_attempt_count));
        maybe_record_scalar_mismatch(
            recorder,
            ImportValidationMismatchCategory::hint,
            entity,
            "unresolved_payload_attempt_budget_exhausted",
            legacy.hint_search_state.unresolved_payload_attempt_budget_exhausted,
            unified.hint_search_state.unresolved_payload_attempt_budget_exhausted);
    }

    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::connection, entity, "has_flow_a", legacy.flow_a.has_value(), unified.flow_a.has_value());
    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::connection, entity, "has_flow_b", legacy.flow_b.has_value(), unified.flow_b.has_value());
    if (legacy.flow_a.has_value() && unified.flow_a.has_value()) {
        compare_flow(recorder, entity + ".flow_a", *legacy.flow_a, *unified.flow_a);
    }
    if (legacy.flow_b.has_value() && unified.flow_b.has_value()) {
        compare_flow(recorder, entity + ".flow_b", *legacy.flow_b, *unified.flow_b);
    }
}

void compare_connection(
    MismatchRecorder& recorder,
    const std::string& entity,
    const ImportValidationConnectionSnapshotV6& legacy,
    const ImportValidationConnectionSnapshotV6& unified,
    const bool include_hints
) {
    if (legacy.key != unified.key) {
        recorder.record(
            ImportValidationMismatchCategory::connection,
            entity,
            "key",
            format_connection_key(legacy.key, legacy.protocol_path),
            format_connection_key(unified.key, unified.protocol_path));
    }
    if (!(legacy.protocol_path == unified.protocol_path)) {
        recorder.record(
            ImportValidationMismatchCategory::connection,
            entity,
            "protocol_path",
            format_protocol_path(legacy.protocol_path),
            format_protocol_path(unified.protocol_path));
    }
    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::connection, entity, "packet_count", legacy.packet_count, unified.packet_count);
    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::connection, entity, "total_bytes", legacy.total_bytes, unified.total_bytes);
    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::connection, entity, "has_fragmented_packets", legacy.has_fragmented_packets, unified.has_fragmented_packets);
    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::connection, entity, "fragmented_packet_count", legacy.fragmented_packet_count, unified.fragmented_packet_count);

    if (include_hints) {
        maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::hint, entity, "protocol_hint", static_cast<int>(legacy.protocol_hint), static_cast<int>(unified.protocol_hint));
        maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::hint, entity, "service_hint", legacy.service_hint, unified.service_hint);
        maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::hint, entity, "quic_version", static_cast<int>(legacy.quic_version), static_cast<int>(unified.quic_version));
        maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::hint, entity, "tls_version", static_cast<int>(legacy.tls_version), static_cast<int>(unified.tls_version));
        maybe_record_scalar_mismatch(
            recorder,
            ImportValidationMismatchCategory::hint,
            entity,
            "unresolved_payload_attempt_count",
            static_cast<unsigned int>(legacy.hint_search_state.unresolved_payload_attempt_count),
            static_cast<unsigned int>(unified.hint_search_state.unresolved_payload_attempt_count));
        maybe_record_scalar_mismatch(
            recorder,
            ImportValidationMismatchCategory::hint,
            entity,
            "unresolved_payload_attempt_budget_exhausted",
            legacy.hint_search_state.unresolved_payload_attempt_budget_exhausted,
            unified.hint_search_state.unresolved_payload_attempt_budget_exhausted);
    }

    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::connection, entity, "has_flow_a", legacy.flow_a.has_value(), unified.flow_a.has_value());
    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::connection, entity, "has_flow_b", legacy.flow_b.has_value(), unified.flow_b.has_value());
    if (legacy.flow_a.has_value() && unified.flow_a.has_value()) {
        compare_flow(recorder, entity + ".flow_a", *legacy.flow_a, *unified.flow_a);
    }
    if (legacy.flow_b.has_value() && unified.flow_b.has_value()) {
        compare_flow(recorder, entity + ".flow_b", *legacy.flow_b, *unified.flow_b);
    }
}

}  // namespace

std::string format_import_validation_mismatch_category(
    const ImportValidationMismatchCategory category
) {
    switch (category) {
    case ImportValidationMismatchCategory::summary:
        return "summary";
    case ImportValidationMismatchCategory::registry:
        return "registry";
    case ImportValidationMismatchCategory::connection:
        return "connection";
    case ImportValidationMismatchCategory::flow:
        return "flow";
    case ImportValidationMismatchCategory::packet_ref:
        return "packet_ref";
    case ImportValidationMismatchCategory::unrecognized:
        return "unrecognized";
    case ImportValidationMismatchCategory::hint:
        return "hint";
    }

    return "unknown";
}

ImportValidationCanonicalState canonicalize_capture_state(
    const CaptureState& state,
    const bool include_hints
) {
    ImportValidationCanonicalState snapshot {
        .summary = state.summary,
    };

    snapshot.protocol_registry_paths.reserve(state.protocol_path_registry.paths().size());
    for (const auto& path : state.protocol_path_registry.paths()) {
        snapshot.protocol_registry_paths.push_back(path);
    }

    auto ipv4_connections = state.ipv4_connections.list();
    std::sort(
        ipv4_connections.begin(),
        ipv4_connections.end(),
        [](const ConnectionV4* lhs, const ConnectionV4* rhs) {
            return lhs->key < rhs->key;
        });
    for (const auto* connection : ipv4_connections) {
        snapshot.ipv4_connections.push_back(snapshot_connection(*connection, state.protocol_path_registry, include_hints));
    }

    auto ipv6_connections = state.ipv6_connections.list();
    std::sort(
        ipv6_connections.begin(),
        ipv6_connections.end(),
        [](const ConnectionV6* lhs, const ConnectionV6* rhs) {
            return lhs->key < rhs->key;
        });
    for (const auto* connection : ipv6_connections) {
        snapshot.ipv6_connections.push_back(snapshot_connection(*connection, state.protocol_path_registry, include_hints));
    }

    snapshot.unrecognized_packets.reserve(state.unrecognized_packets.size());
    for (const auto& record : state.unrecognized_packets) {
        snapshot.unrecognized_packets.push_back(ImportValidationUnrecognizedSnapshot {
            .packet = record.packet,
            .reason_text = record.reason_text,
        });
    }

    return snapshot;
}

ImportValidationCompareResult compare_canonical_states(
    const ImportValidationCanonicalState& legacy,
    const ImportValidationCanonicalState& unified,
    const ImportValidationOptions& options
) {
    ImportValidationCompareResult result {
        .success = true,
        .parity = true,
    };
    MismatchRecorder recorder {
        .limit = options.max_reported_mismatches,
    };

    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::summary, "summary", "packet_count", legacy.summary.packet_count, unified.summary.packet_count);
    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::summary, "summary", "flow_count", legacy.summary.flow_count, unified.summary.flow_count);
    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::summary, "summary", "total_bytes", legacy.summary.total_bytes, unified.summary.total_bytes);

    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::registry, "registry", "size", legacy.protocol_registry_paths.size(), unified.protocol_registry_paths.size());
    const auto shared_registry_size = std::min(legacy.protocol_registry_paths.size(), unified.protocol_registry_paths.size());
    for (std::size_t index = 0U; index < shared_registry_size; ++index) {
        if (legacy.protocol_registry_paths[index] == unified.protocol_registry_paths[index]) {
            continue;
        }

        recorder.record(
            ImportValidationMismatchCategory::registry,
            "registry[" + std::to_string(index + 1U) + ']',
            "protocol_path",
            format_protocol_path(legacy.protocol_registry_paths[index]),
            format_protocol_path(unified.protocol_registry_paths[index]));
    }

    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::connection, "ipv4_connections", "size", legacy.ipv4_connections.size(), unified.ipv4_connections.size());
    const auto shared_ipv4 = std::min(legacy.ipv4_connections.size(), unified.ipv4_connections.size());
    for (std::size_t index = 0U; index < shared_ipv4; ++index) {
        compare_connection(recorder, "ipv4_connection[" + std::to_string(index) + ']', legacy.ipv4_connections[index], unified.ipv4_connections[index], options.include_hints);
    }

    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::connection, "ipv6_connections", "size", legacy.ipv6_connections.size(), unified.ipv6_connections.size());
    const auto shared_ipv6 = std::min(legacy.ipv6_connections.size(), unified.ipv6_connections.size());
    for (std::size_t index = 0U; index < shared_ipv6; ++index) {
        compare_connection(recorder, "ipv6_connection[" + std::to_string(index) + ']', legacy.ipv6_connections[index], unified.ipv6_connections[index], options.include_hints);
    }

    maybe_record_scalar_mismatch(recorder, ImportValidationMismatchCategory::unrecognized, "unrecognized", "size", legacy.unrecognized_packets.size(), unified.unrecognized_packets.size());
    const auto shared_unrecognized = std::min(legacy.unrecognized_packets.size(), unified.unrecognized_packets.size());
    for (std::size_t index = 0U; index < shared_unrecognized; ++index) {
        const auto& legacy_record = legacy.unrecognized_packets[index];
        const auto& unified_record = unified.unrecognized_packets[index];
        if (!(legacy_record.packet == unified_record.packet)) {
            recorder.record(
                ImportValidationMismatchCategory::unrecognized,
                "unrecognized[" + std::to_string(index) + ']',
                "packet_ref",
                format_packet_ref(legacy_record.packet),
                format_packet_ref(unified_record.packet));
        }
        if (legacy_record.reason_text != unified_record.reason_text) {
            recorder.record(
                ImportValidationMismatchCategory::unrecognized,
                "unrecognized[" + std::to_string(index) + ']',
                "reason_text",
                legacy_record.reason_text,
                unified_record.reason_text);
        }
    }

    result.mismatch_count = recorder.total_count;
    result.mismatches = std::move(recorder.mismatches);
    result.parity = result.mismatch_count == 0U;
    return result;
}

ImportValidationRunResult run_legacy_import_validation(
    const std::filesystem::path& capture_path,
    const ImportValidationOptions& options
) {
    return run_import_mode(
        capture_path,
        options,
        true,
        [&capture_path, &options]() {
            return run_legacy_execution(capture_path, options);
        });
}

ImportValidationRunResult run_unified_import_validation(
    const std::filesystem::path& capture_path,
    const ImportValidationOptions& options
) {
    return run_import_mode(
        capture_path,
        options,
        true,
        [&capture_path, &options]() {
            return run_unified_execution(capture_path, options);
        });
}

ImportValidationCompareResult compare_import_validation(
    const std::filesystem::path& capture_path,
    const ImportValidationOptions& options
) {
    ImportValidationCompareResult result {};

    const auto legacy = run_import_mode(
        capture_path,
        options,
        false,
        [&capture_path, &options]() {
            return run_legacy_execution(capture_path, options);
        });
    if (!legacy.success) {
        result.error_text = legacy.error_text;
        return result;
    }

    const auto unified = run_import_mode(
        capture_path,
        options,
        false,
        [&capture_path, &options]() {
            return run_unified_execution(capture_path, options);
        });
    if (!unified.success) {
        result.error_text = unified.error_text;
        return result;
    }

    result = compare_canonical_states(legacy.canonical_state, unified.canonical_state, options);
    result.success = true;
    result.legacy_metrics = legacy.metrics;
    result.unified_metrics = unified.metrics;
    result.legacy_metrics.peak_memory_bytes = std::nullopt;
    result.unified_metrics.peak_memory_bytes = std::nullopt;
    return result;
}

}  // namespace pfl
