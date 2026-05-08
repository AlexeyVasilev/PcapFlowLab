#include "core/services/FlowExportService.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <vector>

#include "core/index/CaptureIndex.h"
#include "core/io/CaptureFilePacketReader.h"
#include "core/io/LinkType.h"
#include "core/io/PcapNgReader.h"
#include "core/io/PcapReader.h"
#include "core/io/PcapWriter.h"

namespace pfl {

namespace {

constexpr std::uint32_t kClassicPcapLittleEndianMagic = 0xa1b2c3d4U;
constexpr std::uint16_t kPcapVersionMajor = 2U;
constexpr std::uint16_t kPcapVersionMinor = 4U;
constexpr std::uint32_t kPcapSnapLength = 65535U;
constexpr std::size_t kProgressReportPacketInterval = 1000U;

void set_error_text(std::string* out_error_text, std::string message) {
    if (out_error_text != nullptr) {
        *out_error_text = message;
    }
}

std::string path_text(const std::filesystem::path& path) {
    return path.generic_string();
}

std::string reader_failure_text(const OpenFailureInfo& failure) {
    std::string text = "Source read failure";
    if (!failure.reason.empty()) {
        text += ": ";
        text += failure.reason;
    }
    if (failure.has_packet_index) {
        text += " (packet ";
        text += std::to_string(failure.packet_index);
        text += ')';
    }
    return text;
}

void append_u16_le(std::vector<std::uint8_t>& out, const std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xffU));
    out.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
}

void append_u32_le(std::vector<std::uint8_t>& out, const std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xffU));
    out.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
}

std::vector<std::uint8_t> build_pcap_global_header_bytes(const std::uint32_t link_type) {
    std::vector<std::uint8_t> bytes {};
    bytes.reserve(24U);
    append_u32_le(bytes, kClassicPcapLittleEndianMagic);
    append_u16_le(bytes, kPcapVersionMajor);
    append_u16_le(bytes, kPcapVersionMinor);
    append_u32_le(bytes, 0U);
    append_u32_le(bytes, 0U);
    append_u32_le(bytes, kPcapSnapLength);
    append_u32_le(bytes, link_type);
    return bytes;
}

void serialize_pcap_packet_record(const RawPcapPacket& packet, std::vector<std::uint8_t>& out) {
    out.clear();
    out.reserve(16U + packet.bytes.size());
    append_u32_le(out, packet.ts_sec);
    append_u32_le(out, packet.ts_usec);
    append_u32_le(out, packet.captured_length);
    append_u32_le(out, packet.original_length);
    out.insert(out.end(), packet.bytes.begin(), packet.bytes.end());
}

template <typename Reader>
bool export_marked_packets_with_reader(
    Reader& reader,
    const std::filesystem::path& output_path,
    std::span<const std::uint8_t> packet_selection
) {
    PcapWriter writer {};
    bool writer_open = false;
    auto remaining_marked_packets = static_cast<std::size_t>(std::count_if(
        packet_selection.begin(),
        packet_selection.end(),
        [](const std::uint8_t marker) { return marker != 0U; }
    ));

    if (remaining_marked_packets == 0U) {
        return false;
    }

    while (const auto raw_packet = reader.read_next()) {
        if (raw_packet->packet_index >= packet_selection.size()) {
            break;
        }

        if (packet_selection[static_cast<std::size_t>(raw_packet->packet_index)] == 0U) {
            continue;
        }

        if (!writer_open) {
            if (!writer.open(output_path, raw_packet->data_link_type)) {
                return false;
            }
            writer_open = true;
        }

        const PacketRef packet_ref {
            .packet_index = raw_packet->packet_index,
            .byte_offset = raw_packet->data_offset,
            .data_link_type = raw_packet->data_link_type,
            .captured_length = raw_packet->captured_length,
            .original_length = raw_packet->original_length,
            .ts_sec = raw_packet->ts_sec,
            .ts_usec = raw_packet->ts_usec,
        };

        if (!writer.write_packet(packet_ref, raw_packet->bytes)) {
            writer.close();
            return false;
        }

        --remaining_marked_packets;
        if (remaining_marked_packets == 0U) {
            writer.close();
            return true;
        }
    }

    if (!writer_open) {
        return false;
    }

    writer.close();
    return remaining_marked_packets == 0U && !reader.has_error();
}

class BufferedPerFlowPcapExporter {
public:
    BufferedPerFlowPcapExporter(std::span<const PerFlowExportTarget> targets, const PerFlowExportOptions& options)
        : buffer_budget_bytes_(std::max<std::size_t>(1U, options.buffer_budget_bytes)),
          max_open_file_handles_(std::max<std::size_t>(1U, options.max_open_file_handles)) {
        states_.reserve(targets.size());
        for (const auto& target : targets) {
            states_.push_back(FlowState {
                .export_flow_id = target.export_flow_id,
                .output_path = target.output_path,
            });
        }
    }

    ~BufferedPerFlowPcapExporter() {
        close_all_handles();
    }

    bool append_packet(const RawPcapPacket& packet, const std::uint32_t owner, std::string* out_error_text) {
        if (owner == 0U) {
            set_error_text(out_error_text, "Internal smart export ownership error: packet owner is zero.");
            return false;
        }

        const auto target_index = static_cast<std::size_t>(owner - 1U);
        if (target_index >= states_.size() || states_[target_index].export_flow_id != owner) {
            set_error_text(out_error_text, "Internal smart export ownership error: invalid export-flow id.");
            return false;
        }

        auto& state = states_[target_index];
        if (!state.link_type_initialized) {
            state.link_type = packet.data_link_type;
            state.link_type_initialized = true;
        }

        serialize_pcap_packet_record(packet, packet_record_scratch_);
        const auto record_size = packet_record_scratch_.size();

        if (record_size > buffer_budget_bytes_) {
            if (!flush_state_buffer(state, out_error_text)) {
                return false;
            }
            if (!append_bytes_to_file(state, packet_record_scratch_, out_error_text)) {
                return false;
            }
        } else {
            if (!ensure_global_buffer_budget(record_size, owner, out_error_text)) {
                return false;
            }

            state.buffer.insert(state.buffer.end(), packet_record_scratch_.begin(), packet_record_scratch_.end());
            state.buffered_bytes = state.buffer.size();
            total_buffered_bytes_ += record_size;
            state.last_buffer_touch = ++buffer_touch_generation_;
        }

        ++state.exported_packet_count;
        state.exported_captured_bytes += packet.captured_length;
        state.exported_original_bytes += packet.original_length;
        ++exported_packets_written_;
        return true;
    }

    bool flush_all(std::string* out_error_text) {
        for (auto& state : states_) {
            if (!flush_state_buffer(state, out_error_text)) {
                return false;
            }
        }

        close_all_handles();
        return true;
    }

    [[nodiscard]] std::uint64_t exported_packets_written() const noexcept {
        return exported_packets_written_;
    }

private:
    struct FlowState {
        std::uint32_t export_flow_id {0};
        std::filesystem::path output_path {};
        bool file_initialized {false};
        bool link_type_initialized {false};
        std::uint32_t link_type {kLinkTypeEthernet};
        std::vector<std::uint8_t> buffer {};
        std::size_t buffered_bytes {0};
        std::uint64_t exported_packet_count {0};
        std::uint64_t exported_captured_bytes {0};
        std::uint64_t exported_original_bytes {0};
        std::uint64_t last_buffer_touch {0};
        std::uint64_t last_handle_touch {0};
        bool handle_open {false};
        std::ofstream handle {};
    };

    [[nodiscard]] FlowState* find_lru_buffer_victim(const std::uint32_t preferred_flow_id) {
        FlowState* fallback = nullptr;
        for (auto& state : states_) {
            if (state.buffer.empty()) {
                continue;
            }

            if (state.export_flow_id != preferred_flow_id &&
                (fallback == nullptr || state.last_buffer_touch < fallback->last_buffer_touch)) {
                fallback = &state;
            }
        }
        if (fallback != nullptr) {
            return fallback;
        }

        FlowState* oldest = nullptr;
        for (auto& state : states_) {
            if (state.buffer.empty()) {
                continue;
            }

            if (oldest == nullptr || state.last_buffer_touch < oldest->last_buffer_touch) {
                oldest = &state;
            }
        }

        return oldest;
    }

    [[nodiscard]] FlowState* find_lru_open_handle() {
        FlowState* oldest = nullptr;
        for (auto& state : states_) {
            if (!state.handle_open) {
                continue;
            }

            if (oldest == nullptr || state.last_handle_touch < oldest->last_handle_touch) {
                oldest = &state;
            }
        }
        return oldest;
    }

    void release_state_buffer_memory(FlowState& state) {
        if (state.buffer.empty()) {
            state.buffered_bytes = 0U;
            return;
        }

        total_buffered_bytes_ -= state.buffer.size();
        std::vector<std::uint8_t> released {};
        state.buffer.swap(released);
        state.buffered_bytes = 0U;
    }

    bool ensure_global_buffer_budget(
        const std::size_t additional_bytes,
        const std::uint32_t preferred_flow_id,
        std::string* out_error_text
    ) {
        while (total_buffered_bytes_ + additional_bytes > buffer_budget_bytes_) {
            auto* victim = find_lru_buffer_victim(preferred_flow_id);
            if (victim == nullptr) {
                set_error_text(out_error_text, "Smart export buffer budget could not be satisfied.");
                return false;
            }

            if (!flush_state_buffer(*victim, out_error_text)) {
                return false;
            }
        }

        return true;
    }

    bool ensure_output_handle_open(FlowState& state, std::string* out_error_text) {
        if (state.handle_open) {
            state.last_handle_touch = ++handle_touch_generation_;
            return true;
        }

        while (open_handle_count_ >= max_open_file_handles_) {
            auto* lru_handle = find_lru_open_handle();
            if (lru_handle == nullptr) {
                set_error_text(out_error_text, "Internal smart export error: open file-handle cache is inconsistent.");
                return false;
            }

            lru_handle->handle.close();
            lru_handle->handle_open = false;
            --open_handle_count_;
        }

        if (!state.file_initialized) {
            if (!state.link_type_initialized) {
                set_error_text(out_error_text, "Internal smart export error: per-flow file link type is unavailable.");
                return false;
            }

            state.handle = std::ofstream(state.output_path, std::ios::binary | std::ios::trunc);
            if (!state.handle.is_open()) {
                set_error_text(out_error_text, "Failed to create output file: " + path_text(state.output_path));
                return false;
            }

            const auto header_bytes = build_pcap_global_header_bytes(state.link_type);
            state.handle.write(reinterpret_cast<const char*>(header_bytes.data()), static_cast<std::streamsize>(header_bytes.size()));
            if (!state.handle.good()) {
                state.handle.close();
                set_error_text(out_error_text, "Failed to initialize output file: " + path_text(state.output_path));
                return false;
            }

            state.file_initialized = true;
        } else {
            state.handle = std::ofstream(state.output_path, std::ios::binary | std::ios::app);
            if (!state.handle.is_open()) {
                set_error_text(out_error_text, "Failed to reopen output file for append: " + path_text(state.output_path));
                return false;
            }
        }

        state.handle_open = true;
        state.last_handle_touch = ++handle_touch_generation_;
        ++open_handle_count_;
        return true;
    }

    bool append_bytes_to_file(FlowState& state, std::span<const std::uint8_t> bytes, std::string* out_error_text) {
        if (bytes.empty()) {
            return true;
        }

        if (!ensure_output_handle_open(state, out_error_text)) {
            return false;
        }

        state.handle.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!state.handle.good()) {
            set_error_text(out_error_text, "Failed to append to output file: " + path_text(state.output_path));
            return false;
        }

        state.last_handle_touch = ++handle_touch_generation_;
        return true;
    }

    bool flush_state_buffer(FlowState& state, std::string* out_error_text) {
        if (state.buffer.empty()) {
            return true;
        }

        if (!append_bytes_to_file(state, state.buffer, out_error_text)) {
            return false;
        }

        release_state_buffer_memory(state);
        return true;
    }

    void close_all_handles() {
        for (auto& state : states_) {
            if (state.handle_open) {
                state.handle.close();
                state.handle_open = false;
            }
        }
        open_handle_count_ = 0U;
    }

    std::size_t buffer_budget_bytes_ {0};
    std::size_t max_open_file_handles_ {0};
    std::vector<FlowState> states_ {};
    std::vector<std::uint8_t> packet_record_scratch_ {};
    std::size_t total_buffered_bytes_ {0};
    std::size_t open_handle_count_ {0};
    std::uint64_t buffer_touch_generation_ {0};
    std::uint64_t handle_touch_generation_ {0};
    std::uint64_t exported_packets_written_ {0};
};

template <typename Reader>
bool export_owned_packets_with_reader(
    Reader& reader,
    std::span<const PerFlowExportTarget> targets,
    std::span<const std::uint32_t> packet_owner,
    const PerFlowExportOptions& options,
    std::string* out_error_text
) {
    auto remaining_owned_packets = static_cast<std::size_t>(std::count_if(
        packet_owner.begin(),
        packet_owner.end(),
        [](const std::uint32_t owner) { return owner != 0U; }
    ));
    if (remaining_owned_packets == 0U) {
        set_error_text(out_error_text, "No packets were selected for per-flow smart export.");
        return false;
    }
    if (targets.empty()) {
        set_error_text(out_error_text, "No per-flow export targets were prepared.");
        return false;
    }

    std::size_t total_packets_to_scan = 0U;
    for (std::size_t index = packet_owner.size(); index > 0U; --index) {
        if (packet_owner[index - 1U] != 0U) {
            total_packets_to_scan = index;
            break;
        }
    }

    BufferedPerFlowPcapExporter exporter {targets, options};
    if (options.progress_callback) {
        options.progress_callback(PerFlowExportProgress {
            .packets_processed = 0U,
            .total_packets_to_scan = static_cast<std::uint64_t>(total_packets_to_scan),
            .exported_packets_written = 0U,
        });
    }

    while (const auto raw_packet = reader.read_next()) {
        const auto processed_packets = raw_packet->packet_index + 1U;
        if (raw_packet->packet_index >= packet_owner.size()) {
            break;
        }

        const auto owner = packet_owner[static_cast<std::size_t>(raw_packet->packet_index)];
        if (owner != 0U) {
            if (!exporter.append_packet(*raw_packet, owner, out_error_text)) {
                return false;
            }

            --remaining_owned_packets;
            if (remaining_owned_packets == 0U) {
                if (!exporter.flush_all(out_error_text)) {
                    return false;
                }

                if (options.progress_callback) {
                    options.progress_callback(PerFlowExportProgress {
                        .packets_processed = static_cast<std::uint64_t>(total_packets_to_scan),
                        .total_packets_to_scan = static_cast<std::uint64_t>(total_packets_to_scan),
                        .exported_packets_written = exporter.exported_packets_written(),
                    });
                }
                return true;
            }
        }

        if (options.progress_callback &&
            ((processed_packets % kProgressReportPacketInterval) == 0U || processed_packets >= total_packets_to_scan)) {
            options.progress_callback(PerFlowExportProgress {
                .packets_processed = processed_packets,
                .total_packets_to_scan = static_cast<std::uint64_t>(total_packets_to_scan),
                .exported_packets_written = exporter.exported_packets_written(),
            });
        }
    }

    if (reader.has_error()) {
        set_error_text(out_error_text, reader_failure_text(reader.last_error()));
        return false;
    }

    if (remaining_owned_packets != 0U) {
        set_error_text(out_error_text, "Source scan ended before all selected packets were exported.");
        return false;
    }

    if (!exporter.flush_all(out_error_text)) {
        return false;
    }

    if (options.progress_callback) {
        options.progress_callback(PerFlowExportProgress {
            .packets_processed = static_cast<std::uint64_t>(total_packets_to_scan),
            .total_packets_to_scan = static_cast<std::uint64_t>(total_packets_to_scan),
            .exported_packets_written = exporter.exported_packets_written(),
        });
    }
    return true;
}

}  // namespace

bool FlowExportService::export_packets_to_pcap(const std::filesystem::path& output_path,
                                               std::span<const PacketRef> packets,
                                               const std::filesystem::path& source_capture_path) const {
    CaptureFilePacketReader reader {source_capture_path};
    if (!reader.is_open()) {
        return false;
    }

    PcapWriter writer {};
    const auto link_type = packets.empty() ? kLinkTypeEthernet : packets.front().data_link_type;
    if (!writer.open(output_path, link_type)) {
        return false;
    }

    std::vector<std::uint8_t> bytes {};
    for (const auto& packet : packets) {
        if (!reader.read_packet_data(packet, bytes)) {
            writer.close();
            return false;
        }

        if (!writer.write_packet(packet, bytes)) {
            writer.close();
            return false;
        }
    }

    writer.close();
    return true;
}

bool FlowExportService::export_marked_packets_to_pcap(
    const std::filesystem::path& output_path,
    std::span<const std::uint8_t> packet_selection,
    const std::filesystem::path& source_capture_path
) const {
    if (packet_selection.empty()) {
        return false;
    }

    switch (detect_capture_source_format(source_capture_path)) {
    case CaptureSourceFormat::classic_pcap: {
        PcapReader reader {};
        if (!reader.open(source_capture_path)) {
            return false;
        }

        return export_marked_packets_with_reader(reader, output_path, packet_selection);
    }
    case CaptureSourceFormat::pcapng: {
        PcapNgReader reader {};
        if (!reader.open(source_capture_path)) {
            return false;
        }

        return export_marked_packets_with_reader(reader, output_path, packet_selection);
    }
    default:
        return false;
    }
}

bool FlowExportService::export_owned_packets_to_pcaps(
    std::span<const PerFlowExportTarget> targets,
    std::span<const std::uint32_t> packet_owner,
    const std::filesystem::path& source_capture_path,
    const PerFlowExportOptions& options,
    std::string* out_error_text
) const {
    if (targets.empty()) {
        set_error_text(out_error_text, "No per-flow export targets were prepared.");
        return false;
    }
    if (packet_owner.empty()) {
        set_error_text(out_error_text, "No packets were selected for per-flow smart export.");
        return false;
    }

    switch (detect_capture_source_format(source_capture_path)) {
    case CaptureSourceFormat::classic_pcap: {
        PcapReader reader {};
        if (!reader.open(source_capture_path)) {
            set_error_text(out_error_text, reader_failure_text(reader.last_error()));
            return false;
        }

        return export_owned_packets_with_reader(reader, targets, packet_owner, options, out_error_text);
    }
    case CaptureSourceFormat::pcapng: {
        PcapNgReader reader {};
        if (!reader.open(source_capture_path)) {
            set_error_text(out_error_text, reader_failure_text(reader.last_error()));
            return false;
        }

        return export_owned_packets_with_reader(reader, targets, packet_owner, options, out_error_text);
    }
    default:
        set_error_text(out_error_text, "Unsupported source capture format for per-flow smart export.");
        return false;
    }
}

}  // namespace pfl
