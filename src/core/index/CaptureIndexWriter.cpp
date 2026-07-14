#include "core/index/CaptureIndexWriter.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <limits>
#include <optional>
#include <streambuf>
#include <string>
#include <system_error>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

#include "core/index/CaptureIndex.h"
#include "core/index/Serialization.h"

namespace pfl {

namespace {

constexpr std::uint64_t kFixedIndexSectionCountExcludingConnections = 4U;
constexpr std::uint64_t kMinimumConnectionSectionPayloadBytes = 8U;

[[nodiscard]] std::uint64_t stream_offset(std::ofstream& stream) {
    const auto current = stream.tellp();
    if (current < 0) {
        return 0U;
    }

    return static_cast<std::uint64_t>(current);
}

void set_error_text(std::string* out_error_text, const std::string& message) {
    if (out_error_text != nullptr) {
        *out_error_text = message;
    }
}

[[nodiscard]] bool should_cancel(const CaptureIndexWriteOptions& options) {
    return options.cancel_requested && options.cancel_requested();
}

void deliver_progress(
    const CaptureIndexWriteOptions& options,
    const CaptureIndexWritePhase phase,
    const std::string& phase_text,
    const std::uint64_t completed_sections,
    const std::uint64_t total_sections,
    const std::uint64_t phase_items_processed,
    const std::uint64_t phase_items_total,
    const std::uint64_t bytes_written
) {
    if (!options.progress_callback) {
        return;
    }

    CaptureIndexWriteProgress progress {};
    progress.phase = phase;
    progress.phase_text = phase_text;
    progress.completed_sections = completed_sections;
    progress.total_sections = total_sections;
    progress.phase_items_processed = phase_items_processed;
    progress.phase_items_total = phase_items_total;
    progress.bytes_written = bytes_written;
    options.progress_callback(progress);
}

class ThrottledProgressReporter final {
public:
    explicit ThrottledProgressReporter(const CaptureIndexWriteOptions& options)
        : options_(options) {
    }

    void report(
        const CaptureIndexWritePhase phase,
        const std::string& phase_text,
        const std::uint64_t completed_sections,
        const std::uint64_t total_sections,
        const std::uint64_t phase_items_processed,
        const std::uint64_t phase_items_total,
        const std::uint64_t bytes_written,
        const bool force = false
    ) {
        if (!options_.progress_callback) {
            return;
        }

        CaptureIndexWriteProgress progress {};
        progress.phase = phase;
        progress.phase_text = phase_text;
        progress.completed_sections = completed_sections;
        progress.total_sections = total_sections;
        progress.phase_items_processed = phase_items_processed;
        progress.phase_items_total = phase_items_total;
        progress.bytes_written = bytes_written;

        const auto now = std::chrono::steady_clock::now();
        const bool first_report = !last_report_.has_value();
        const bool phase_changed = first_report ||
            last_report_->phase != progress.phase ||
            last_report_->phase_text != progress.phase_text;
        const bool section_progress_changed = first_report ||
            last_report_->completed_sections != progress.completed_sections ||
            last_report_->total_sections != progress.total_sections;
        const bool item_space_changed = first_report ||
            last_report_->phase_items_total != progress.phase_items_total ||
            progress.phase_items_processed < last_report_->phase_items_processed;
        const bool final_phase_progress =
            (progress.phase_items_total > 0U && progress.phase_items_processed >= progress.phase_items_total) ||
            (progress.total_sections > 0U && progress.completed_sections >= progress.total_sections);
        const bool throttle_elapsed =
            first_report || (now - last_emit_time_) >= kProgressThrottleInterval;

        if (force || phase_changed || section_progress_changed || item_space_changed || final_phase_progress || throttle_elapsed) {
            deliver_progress(
                options_,
                progress.phase,
                progress.phase_text,
                progress.completed_sections,
                progress.total_sections,
                progress.phase_items_processed,
                progress.phase_items_total,
                progress.bytes_written
            );
            last_emit_time_ = now;
        }

        last_report_ = progress;
    }

private:
    static constexpr auto kProgressThrottleInterval = std::chrono::milliseconds(75);

    const CaptureIndexWriteOptions& options_;
    std::optional<CaptureIndexWriteProgress> last_report_ {};
    std::chrono::steady_clock::time_point last_emit_time_ {};
};

[[nodiscard]] std::filesystem::path temp_index_path_for(const std::filesystem::path& index_path) {
    auto temp_path = index_path;
    temp_path += ".writing.tmp";
    return temp_path;
}

bool remove_file_if_exists(const std::filesystem::path& path) {
    std::error_code error {};
    std::filesystem::remove(path, error);
    return !error;
}

bool replace_file_atomically(const std::filesystem::path& source_path, const std::filesystem::path& target_path) {
#ifdef _WIN32
    return ::MoveFileExW(
        source_path.c_str(),
        target_path.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
    ) != 0;
#else
    std::error_code error {};
    std::filesystem::rename(source_path, target_path, error);
    return !error;
#endif
}

template <typename Writer>
bool compute_marshaled_section_size(std::uint64_t& out_size, Writer&& writer) {
    class CountingStreambuf final : public std::streambuf {
    public:
        [[nodiscard]] std::uint64_t bytes_written() const noexcept {
            return bytes_written_;
        }

    protected:
        std::streamsize xsputn(const char*, const std::streamsize count) override {
            if (count > 0) {
                bytes_written_ += static_cast<std::uint64_t>(count);
            }
            return count;
        }

        int overflow(const int ch) override {
            if (ch != EOF) {
                ++bytes_written_;
            }
            return ch;
        }

    private:
        std::uint64_t bytes_written_ {0};
    };

    class CountingOStream final : public std::ostream {
    public:
        CountingOStream()
            : std::ostream(&buffer_) {
        }

        [[nodiscard]] std::uint64_t bytes_written() const noexcept {
            return buffer_.bytes_written();
        }

    private:
        CountingStreambuf buffer_ {};
    };

    CountingOStream stream {};
    if (!writer(stream)) {
        return false;
    }

    out_size = stream.bytes_written();
    return true;
}

template <typename Flow>
[[nodiscard]] std::uint64_t flow_packet_ref_count(const Flow& flow) {
    return static_cast<std::uint64_t>(flow.packets.size());
}

template <typename Connection>
[[nodiscard]] std::uint64_t connection_packet_ref_count(const Connection& connection) {
    return (connection.has_flow_a ? flow_packet_ref_count(connection.flow_a) : 0U) +
           (connection.has_flow_b ? flow_packet_ref_count(connection.flow_b) : 0U);
}

[[nodiscard]] constexpr std::uint64_t serialized_u8_size() noexcept {
    return 1U;
}

[[nodiscard]] constexpr std::uint64_t serialized_u16_size() noexcept {
    return 2U;
}

[[nodiscard]] constexpr std::uint64_t serialized_u32_size() noexcept {
    return 4U;
}

[[nodiscard]] constexpr std::uint64_t serialized_u64_size() noexcept {
    return 8U;
}

[[nodiscard]] constexpr std::uint64_t serialized_protocol_id_size() noexcept {
    return serialized_u8_size();
}

[[nodiscard]] constexpr std::uint64_t serialized_protocol_hint_size() noexcept {
    return serialized_u8_size();
}

[[nodiscard]] constexpr std::uint64_t serialized_endpoint_key_size(const EndpointKeyV4&) noexcept {
    return serialized_u32_size() + serialized_u16_size();
}

[[nodiscard]] constexpr std::uint64_t serialized_endpoint_key_size(const EndpointKeyV6&) noexcept {
    return 16U + serialized_u16_size();
}

[[nodiscard]] constexpr std::uint64_t serialized_flow_key_size(const FlowKeyV4&) noexcept {
    return serialized_u32_size() +
           serialized_u32_size() +
           serialized_u16_size() +
           serialized_u16_size() +
           serialized_protocol_id_size() +
           serialized_u32_size();
}

[[nodiscard]] constexpr std::uint64_t serialized_flow_key_size(const FlowKeyV6&) noexcept {
    return 16U +
           16U +
           serialized_u16_size() +
           serialized_u16_size() +
           serialized_protocol_id_size() +
           serialized_u32_size();
}

[[nodiscard]] constexpr std::uint64_t serialized_connection_key_size(const ConnectionKeyV4& key) noexcept {
    return serialized_endpoint_key_size(key.first) +
           serialized_endpoint_key_size(key.second) +
           serialized_protocol_id_size() +
           serialized_u32_size();
}

[[nodiscard]] constexpr std::uint64_t serialized_connection_key_size(const ConnectionKeyV6& key) noexcept {
    return serialized_endpoint_key_size(key.first) +
           serialized_endpoint_key_size(key.second) +
           serialized_protocol_id_size() +
           serialized_u32_size();
}

[[nodiscard]] std::optional<std::uint64_t> serialized_string_size(const std::string& value) noexcept {
    if (value.size() > static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)())) {
        return std::nullopt;
    }

    return serialized_u32_size() + static_cast<std::uint64_t>(value.size());
}

[[nodiscard]] constexpr std::uint64_t serialized_packet_ref_size() noexcept {
    return serialized_u64_size() +
           serialized_u32_size() +
           serialized_u32_size() +
           serialized_u64_size() +
           serialized_u32_size() +
           serialized_u32_size() +
           serialized_u32_size() +
           serialized_u32_size() +
           serialized_u8_size() +
           serialized_u8_size();
}

template <typename Flow>
[[nodiscard]] std::optional<std::uint64_t> serialized_flow_size(const Flow& flow) noexcept {
    const auto packet_count = static_cast<std::uint64_t>(flow.packets.size());
    return serialized_flow_key_size(flow.key) +
           serialized_u64_size() +
           serialized_u64_size() +
           serialized_u64_size() +
           (packet_count * serialized_packet_ref_size());
}

template <typename Connection>
[[nodiscard]] std::optional<std::uint64_t> serialized_connection_size(const Connection& connection) noexcept {
    const auto service_hint_size = serialized_string_size(connection.service_hint);
    if (!service_hint_size.has_value()) {
        return std::nullopt;
    }

    auto total = serialized_connection_key_size(connection.key) +
        serialized_u8_size() +
        serialized_u8_size() +
        serialized_u64_size() +
        serialized_u64_size() +
        serialized_u8_size() +
        serialized_u64_size() +
        serialized_protocol_hint_size() +
        *service_hint_size;

    if (connection.has_flow_a) {
        const auto flow_a_size = serialized_flow_size(connection.flow_a);
        if (!flow_a_size.has_value()) {
            return std::nullopt;
        }
        total += *flow_a_size;
    }

    if (connection.has_flow_b) {
        const auto flow_b_size = serialized_flow_size(connection.flow_b);
        if (!flow_b_size.has_value()) {
            return std::nullopt;
        }
        total += *flow_b_size;
    }

    return total;
}

template <typename Connection>
bool write_connection_with_progress(
    std::ostream& stream,
    const Connection& connection,
    std::uint64_t& packets_processed,
    const std::uint64_t total_packets,
    const detail::SerializationProgressCallback& progress_callback
) {
    if (!detail::write_connection(stream, connection)) {
        return false;
    }

    packets_processed += connection_packet_ref_count(connection);
    if ((packets_processed == total_packets || (packets_processed % 4096U) == 0U) &&
        (!progress_callback || !progress_callback(packets_processed, total_packets))) {
        return false;
    }

    return true;
}

template <typename ConnectionPtr>
struct ConnectionChunkRange {
    std::size_t start_index {0};
    std::size_t connection_count {0};
    std::uint64_t payload_size {kMinimumConnectionSectionPayloadBytes};
};

template <typename ConnectionPtr>
struct ConnectionChunkPlan {
    std::vector<ConnectionPtr> connections {};
    std::vector<ConnectionChunkRange<ConnectionPtr>> chunks {};
    std::uint64_t total_packets {0};
};

[[nodiscard]] std::uint64_t normalized_connection_section_payload_limit(const CaptureIndexWriteOptions& options) {
    return options.max_connection_section_payload_bytes < kMinimumConnectionSectionPayloadBytes
        ? kMinimumConnectionSectionPayloadBytes
        : options.max_connection_section_payload_bytes;
}

template <typename Table, typename ConnectionPtr>
std::optional<ConnectionChunkPlan<ConnectionPtr>> build_connection_chunk_plan(
    const Table& table,
    const CaptureIndexWriteOptions& options,
    ThrottledProgressReporter& progress_reporter,
    const std::string& label,
    const std::uint64_t completed_sections,
    const std::uint64_t total_sections
) {
    ConnectionChunkPlan<ConnectionPtr> plan {};
    plan.connections = detail::sorted_connections(table);
    const auto payload_limit = normalized_connection_section_payload_limit(options);

    progress_reporter.report(
        CaptureIndexWritePhase::preparing,
        "Preparing " + label,
        completed_sections,
        total_sections,
        0U,
        static_cast<std::uint64_t>(plan.connections.size()),
        0U
    );

    if (should_cancel(options)) {
        return std::nullopt;
    }

    if (plan.connections.empty()) {
        plan.chunks.push_back({});
        return plan;
    }

    ConnectionChunkRange<ConnectionPtr> chunk {};
    chunk.start_index = 0U;
    chunk.connection_count = 0U;
    chunk.payload_size = kMinimumConnectionSectionPayloadBytes;

    for (std::size_t index = 0U; index < plan.connections.size(); ++index) {
        const auto* connection = plan.connections[index];
        plan.total_packets += connection_packet_ref_count(*connection);

        const auto connection_size = serialized_connection_size(*connection);
        if (!connection_size.has_value()) {
            return std::nullopt;
        }

        const bool would_exceed_limit =
            chunk.connection_count > 0U && (chunk.payload_size + *connection_size) > payload_limit;
        if (would_exceed_limit) {
            plan.chunks.push_back(chunk);
            chunk = {};
            chunk.start_index = index;
            chunk.connection_count = 0U;
            chunk.payload_size = kMinimumConnectionSectionPayloadBytes;
        }

        chunk.payload_size += *connection_size;
        ++chunk.connection_count;

        progress_reporter.report(
            CaptureIndexWritePhase::preparing,
            "Preparing " + label,
            completed_sections,
            total_sections,
            static_cast<std::uint64_t>(index + 1U),
            static_cast<std::uint64_t>(plan.connections.size()),
            0U
        );

        if (should_cancel(options)) {
            return std::nullopt;
        }
    }

    plan.chunks.push_back(chunk);
    return plan;
}

template <typename Writer>
bool write_marshaled_section(
    std::ofstream& stream,
    const detail::CaptureIndexSectionId section_id,
    const CaptureIndexWriteOptions& options,
    ThrottledProgressReporter& progress_reporter,
    const std::string& label,
    const std::uint64_t completed_sections,
    const std::uint64_t total_sections,
    const std::uint64_t phase_items_total,
    Writer&& writer,
    std::string* out_error_text
) {
    progress_reporter.report(
        CaptureIndexWritePhase::preparing,
        "Preparing " + label,
        completed_sections,
        total_sections,
        0U,
        phase_items_total,
        stream_offset(stream)
    );
    if (should_cancel(options)) {
        set_error_text(out_error_text, "Index save cancelled by user.");
        return false;
    }

    std::uint64_t payload_size {0};
    if (!compute_marshaled_section_size(payload_size, [&](std::ostream& payload) {
            return writer(
                payload,
                [&](const std::uint64_t processed, const std::uint64_t total) {
                    progress_reporter.report(
                        CaptureIndexWritePhase::preparing,
                        "Preparing " + label,
                        completed_sections,
                        total_sections,
                        processed,
                        total,
                        stream_offset(stream)
                    );
                    return !should_cancel(options);
                }
            );
        })) {
        if (should_cancel(options)) {
            set_error_text(out_error_text, "Index save cancelled by user.");
        } else {
            set_error_text(out_error_text, "Failed to prepare " + label + ".");
        }
        return false;
    }

    progress_reporter.report(
        CaptureIndexWritePhase::writing,
        "Writing " + label,
        completed_sections,
        total_sections,
        0U,
        phase_items_total,
        stream_offset(stream)
    );
    if (should_cancel(options)) {
        set_error_text(out_error_text, "Index save cancelled by user.");
        return false;
    }

    if (!detail::write_u32(stream, static_cast<std::uint32_t>(section_id)) ||
        !detail::write_u64(stream, payload_size)) {
        set_error_text(out_error_text, "Failed to write " + label + " header.");
        return false;
    }

    if (!writer(
            stream,
            [&](const std::uint64_t processed, const std::uint64_t total) {
                progress_reporter.report(
                    CaptureIndexWritePhase::writing,
                    "Writing " + label,
                    completed_sections,
                    total_sections,
                    processed,
                    total,
                    stream_offset(stream)
                );
                return !should_cancel(options);
            }
        )) {
        if (should_cancel(options)) {
            set_error_text(out_error_text, "Index save cancelled by user.");
        } else {
            set_error_text(out_error_text, "Failed to write " + label + ".");
        }
        return false;
    }

    progress_reporter.report(
        CaptureIndexWritePhase::writing,
        "Writing " + label,
        completed_sections + 1U,
        total_sections,
        phase_items_total,
        phase_items_total,
        stream_offset(stream),
        true
    );
    return true;
}

template <typename ConnectionPtr>
bool write_chunked_connection_sections(
    std::ofstream& stream,
    const detail::CaptureIndexSectionId section_id,
    const std::string& label,
    const ConnectionChunkPlan<ConnectionPtr>& plan,
    const CaptureIndexWriteOptions& options,
    ThrottledProgressReporter& progress_reporter,
    std::uint64_t& completed_sections,
    const std::uint64_t total_sections,
    std::string* out_error_text
) {
    std::uint64_t processed_packets {0};
    if (plan.total_packets == 0U) {
        progress_reporter.report(
            CaptureIndexWritePhase::writing,
            "Writing " + label,
            completed_sections,
            total_sections,
            0U,
            0U,
            stream_offset(stream),
            true
        );
    }

    for (std::size_t chunk_index = 0U; chunk_index < plan.chunks.size(); ++chunk_index) {
        const auto& chunk = plan.chunks[chunk_index];
        const auto chunk_label = plan.chunks.size() > 1U
            ? label + " chunk " + std::to_string(chunk_index + 1U) + "/" + std::to_string(plan.chunks.size())
            : label;

        progress_reporter.report(
            CaptureIndexWritePhase::writing,
            "Writing " + chunk_label,
            completed_sections,
            total_sections,
            processed_packets,
            plan.total_packets,
            stream_offset(stream)
        );

        if (should_cancel(options)) {
            set_error_text(out_error_text, "Index save cancelled by user.");
            return false;
        }

        if (!detail::write_u32(stream, static_cast<std::uint32_t>(section_id)) ||
            !detail::write_u64(stream, chunk.payload_size) ||
            !detail::write_u64(stream, static_cast<std::uint64_t>(chunk.connection_count))) {
            set_error_text(out_error_text, "Failed to write " + chunk_label + " header.");
            return false;
        }

        const auto end_index = chunk.start_index + chunk.connection_count;
        for (std::size_t index = chunk.start_index; index < end_index; ++index) {
            const auto* connection = plan.connections[index];
            if (!write_connection_with_progress(
                    stream,
                    *connection,
                    processed_packets,
                    plan.total_packets,
                    [&](const std::uint64_t processed, const std::uint64_t total) {
                        progress_reporter.report(
                            CaptureIndexWritePhase::writing,
                            "Writing " + chunk_label,
                            completed_sections,
                            total_sections,
                            processed,
                            total,
                            stream_offset(stream)
                        );
                        return !should_cancel(options);
                    })) {
                if (should_cancel(options)) {
                    set_error_text(out_error_text, "Index save cancelled by user.");
                } else {
                    set_error_text(out_error_text, "Failed to write " + chunk_label + ".");
                }
                return false;
            }
        }

        ++completed_sections;
        progress_reporter.report(
            CaptureIndexWritePhase::writing,
            "Writing " + chunk_label,
            completed_sections,
            total_sections,
            processed_packets,
            plan.total_packets,
            stream_offset(stream),
            true
        );
    }

    return true;
}

}  // namespace

bool CaptureIndexWriter::write(
    const std::filesystem::path& index_path,
    const CaptureState& state,
    const std::filesystem::path& source_capture_path
) const {
    return write(index_path, state, source_capture_path, {}, nullptr);
}

bool CaptureIndexWriter::write(
    const std::filesystem::path& index_path,
    const CaptureState& state,
    const std::filesystem::path& source_capture_path,
    const CaptureIndexWriteOptions& options,
    std::string* out_error_text
) const {
    set_error_text(out_error_text, std::string {});
    ThrottledProgressReporter progress_reporter {options};

    CaptureSourceInfo source_info {};
    if (!read_capture_source_info(source_capture_path, source_info)) {
        set_error_text(out_error_text, "Failed to read source capture information.");
        return false;
    }

    const auto ipv4_chunk_plan = build_connection_chunk_plan<ConnectionTableV4, const ConnectionV4*>(
        state.ipv4_connections,
        options,
        progress_reporter,
        "IPv4 connection section",
        0U,
        0U
    );
    if (!ipv4_chunk_plan.has_value()) {
        if (should_cancel(options)) {
            set_error_text(out_error_text, "Index save cancelled by user.");
        } else {
            set_error_text(out_error_text, "Failed to prepare IPv4 connection section.");
        }
        return false;
    }

    const auto ipv6_chunk_plan = build_connection_chunk_plan<ConnectionTableV6, const ConnectionV6*>(
        state.ipv6_connections,
        options,
        progress_reporter,
        "IPv6 connection section",
        0U,
        0U
    );
    if (!ipv6_chunk_plan.has_value()) {
        if (should_cancel(options)) {
            set_error_text(out_error_text, "Index save cancelled by user.");
        } else {
            set_error_text(out_error_text, "Failed to prepare IPv6 connection section.");
        }
        return false;
    }

    const auto total_sections = kFixedIndexSectionCountExcludingConnections +
        static_cast<std::uint64_t>(ipv4_chunk_plan->chunks.size()) +
        static_cast<std::uint64_t>(ipv6_chunk_plan->chunks.size());

    const auto temp_path = temp_index_path_for(index_path);
    remove_file_if_exists(temp_path);

    std::ofstream stream(temp_path, std::ios::binary | std::ios::trunc);
    if (!stream.is_open()) {
        set_error_text(out_error_text, "Failed to create temporary index file.");
        return false;
    }

    auto cleanup_temp = [&]() {
        stream.close();
        remove_file_if_exists(temp_path);
    };

    progress_reporter.report(CaptureIndexWritePhase::preparing, "Preparing index save", 0U, total_sections, 0U, 0U, 0U, true);
    if (should_cancel(options)) {
        cleanup_temp();
        set_error_text(out_error_text, "Index save cancelled by user.");
        return false;
    }

    if (!detail::write_u64(stream, kCaptureIndexMagic) ||
        !detail::write_u16(stream, kCaptureIndexVersion) ||
        !detail::write_u16(stream, 0U)) {
        cleanup_temp();
        set_error_text(out_error_text, "Failed to write index header.");
        return false;
    }

    std::uint64_t completed_sections {0U};
    if (!write_marshaled_section(
            stream,
            detail::CaptureIndexSectionId::source_info,
            options,
            progress_reporter,
            "source info section",
            completed_sections,
            total_sections,
            1U,
            [&](std::ostream& payload, const detail::SerializationProgressCallback&) {
                return detail::write_capture_source_info(payload, source_info);
            },
            out_error_text)) {
        cleanup_temp();
        return false;
    }
    ++completed_sections;

    if (!write_marshaled_section(
            stream,
            detail::CaptureIndexSectionId::summary,
            options,
            progress_reporter,
            "summary section",
            completed_sections,
            total_sections,
            1U,
            [&](std::ostream& payload, const detail::SerializationProgressCallback&) {
                return detail::write_capture_summary(payload, state.summary);
            },
            out_error_text)) {
        cleanup_temp();
        return false;
    }
    ++completed_sections;

    if (!write_marshaled_section(
            stream,
            detail::CaptureIndexSectionId::protocol_paths,
            options,
            progress_reporter,
            "protocol path registry section",
            completed_sections,
            total_sections,
            static_cast<std::uint64_t>(state.protocol_path_registry.size()),
            [&](std::ostream& payload, const detail::SerializationProgressCallback& callback) {
                return detail::write_protocol_path_registry(payload, state.protocol_path_registry, callback);
            },
            out_error_text)) {
        cleanup_temp();
        return false;
    }
    ++completed_sections;

    if (!write_chunked_connection_sections(
            stream,
            detail::CaptureIndexSectionId::ipv4_connections,
            "IPv4 connection section",
            *ipv4_chunk_plan,
            options,
            progress_reporter,
            completed_sections,
            total_sections,
            out_error_text)) {
        cleanup_temp();
        return false;
    }

    if (!write_chunked_connection_sections(
            stream,
            detail::CaptureIndexSectionId::ipv6_connections,
            "IPv6 connection section",
            *ipv6_chunk_plan,
            options,
            progress_reporter,
            completed_sections,
            total_sections,
            out_error_text)) {
        cleanup_temp();
        return false;
    }

    if (!write_marshaled_section(
            stream,
            detail::CaptureIndexSectionId::unrecognized_packets,
            options,
            progress_reporter,
            "unrecognized packet section",
            completed_sections,
            total_sections,
            static_cast<std::uint64_t>(state.unrecognized_packets.size()),
            [&](std::ostream& payload, const detail::SerializationProgressCallback& callback) {
                return detail::write_unrecognized_packet_records(payload, state.unrecognized_packets, callback);
            },
            out_error_text)) {
        cleanup_temp();
        return false;
    }
    ++completed_sections;

    progress_reporter.report(
        CaptureIndexWritePhase::finalizing,
        "Finalizing temporary index file",
        completed_sections,
        total_sections,
        completed_sections,
        total_sections,
        stream_offset(stream),
        true
    );
    if (should_cancel(options)) {
        cleanup_temp();
        set_error_text(out_error_text, "Index save cancelled by user.");
        return false;
    }

    stream.flush();
    if (!stream) {
        cleanup_temp();
        set_error_text(out_error_text, "Failed to flush temporary index file.");
        return false;
    }

    stream.close();
    if (!stream) {
        cleanup_temp();
        set_error_text(out_error_text, "Failed to finalize temporary index file.");
        return false;
    }

    std::error_code temp_size_error {};
    const auto temp_size = std::filesystem::file_size(temp_path, temp_size_error);
    progress_reporter.report(
        CaptureIndexWritePhase::replacing_target,
        "Replacing target index file",
        completed_sections,
        total_sections,
        completed_sections,
        total_sections,
        temp_size_error ? 0U : static_cast<std::uint64_t>(temp_size),
        true
    );
    if (should_cancel(options)) {
        remove_file_if_exists(temp_path);
        set_error_text(out_error_text, "Index save cancelled by user.");
        return false;
    }

    if (!replace_file_atomically(temp_path, index_path)) {
        remove_file_if_exists(temp_path);
        set_error_text(out_error_text, "Failed to replace target index file.");
        return false;
    }

    return true;
}

}  // namespace pfl
