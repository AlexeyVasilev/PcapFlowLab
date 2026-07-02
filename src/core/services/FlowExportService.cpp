#include "core/services/FlowExportService.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <limits>
#include <optional>
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
constexpr std::size_t kCancellationCheckPacketInterval = 1024U;
constexpr std::size_t kPerFlowBufferSlotSizeBytes = 32U * 1024U;

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
    std::span<const std::uint8_t> packet_selection,
    const MarkedPacketExportOptions& options,
    std::string* out_error_text
) {
    PcapWriter writer {};
    bool writer_open = false;
    const auto total_selected_packets = static_cast<std::size_t>(std::count_if(
        packet_selection.begin(),
        packet_selection.end(),
        [](const std::uint8_t marker) { return marker != 0U; }
    ));
    auto remaining_marked_packets = total_selected_packets;

    std::size_t total_packets_to_scan = 0U;
    for (std::size_t index = packet_selection.size(); index > 0U; --index) {
        if (packet_selection[index - 1U] != 0U) {
            total_packets_to_scan = index;
            break;
        }
    }

    if (remaining_marked_packets == 0U) {
        set_error_text(out_error_text, "No packets were selected for smart export.");
        return false;
    }

    if (options.progress_callback) {
        options.progress_callback(MarkedPacketExportProgress {
            .packets_processed = 0U,
            .total_packets_to_scan = static_cast<std::uint64_t>(total_packets_to_scan),
            .exported_packets_written = 0U,
            .total_selected_packets = static_cast<std::uint64_t>(total_selected_packets),
        });
    }

    if (options.cancel_requested && options.cancel_requested()) {
        set_error_text(out_error_text, "Smart export cancelled by user.");
        return false;
    }

    while (const auto raw_packet = reader.read_next()) {
        const auto processed_packets = raw_packet->packet_index + 1U;
        if (options.cancel_requested &&
            ((processed_packets % kCancellationCheckPacketInterval) == 0U) &&
            options.cancel_requested()) {
            writer.close();
            set_error_text(out_error_text, "Smart export cancelled by user.");
            return false;
        }

        if (raw_packet->packet_index >= packet_selection.size()) {
            break;
        }

        if (packet_selection[static_cast<std::size_t>(raw_packet->packet_index)] == 0U) {
            if (options.progress_callback &&
                ((processed_packets % kProgressReportPacketInterval) == 0U || processed_packets >= total_packets_to_scan)) {
                options.progress_callback(MarkedPacketExportProgress {
                    .packets_processed = processed_packets,
                    .total_packets_to_scan = static_cast<std::uint64_t>(total_packets_to_scan),
                    .exported_packets_written = static_cast<std::uint64_t>(total_selected_packets - remaining_marked_packets),
                    .total_selected_packets = static_cast<std::uint64_t>(total_selected_packets),
                });
            }
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
            if (options.progress_callback) {
                options.progress_callback(MarkedPacketExportProgress {
                    .packets_processed = static_cast<std::uint64_t>(total_packets_to_scan),
                    .total_packets_to_scan = static_cast<std::uint64_t>(total_packets_to_scan),
                    .exported_packets_written = static_cast<std::uint64_t>(total_selected_packets),
                    .total_selected_packets = static_cast<std::uint64_t>(total_selected_packets),
                });
            }
            return true;
        }

        if (options.progress_callback &&
            ((processed_packets % kProgressReportPacketInterval) == 0U || processed_packets >= total_packets_to_scan)) {
            options.progress_callback(MarkedPacketExportProgress {
                .packets_processed = processed_packets,
                .total_packets_to_scan = static_cast<std::uint64_t>(total_packets_to_scan),
                .exported_packets_written = static_cast<std::uint64_t>(total_selected_packets - remaining_marked_packets),
                .total_selected_packets = static_cast<std::uint64_t>(total_selected_packets),
            });
        }
    }

    if (options.cancel_requested && options.cancel_requested()) {
        writer.close();
        set_error_text(out_error_text, "Smart export cancelled by user.");
        return false;
    }

    if (reader.has_error()) {
        writer.close();
        set_error_text(out_error_text, reader_failure_text(reader.last_error()));
        return false;
    }
    if (remaining_marked_packets != 0U) {
        writer.close();
        set_error_text(out_error_text, "Source scan ended before all selected packets were exported.");
        return false;
    }
    if (!writer_open) {
        set_error_text(out_error_text, "No packets were selected for smart export.");
        return false;
    }

    writer.close();

    if (options.progress_callback) {
        options.progress_callback(MarkedPacketExportProgress {
            .packets_processed = static_cast<std::uint64_t>(total_packets_to_scan),
            .total_packets_to_scan = static_cast<std::uint64_t>(total_packets_to_scan),
            .exported_packets_written = static_cast<std::uint64_t>(total_selected_packets),
            .total_selected_packets = static_cast<std::uint64_t>(total_selected_packets),
        });
    }
    return true;
}

class BufferedPerFlowPcapExporter {
public:
    BufferedPerFlowPcapExporter(std::span<const PerFlowExportTarget> targets, const PerFlowExportOptions& options)
        : buffer_budget_bytes_(std::max<std::size_t>(1U, options.buffer_budget_bytes)),
          buffer_slot_count_(std::max<std::size_t>(1U, buffer_budget_bytes_ / kPerFlowBufferSlotSizeBytes)),
          max_open_file_handles_(std::max<std::size_t>(1U, options.max_open_file_handles)) {
        states_.reserve(targets.size());
        for (const auto& target : targets) {
            states_.push_back(FlowState {
                .export_flow_id = target.export_flow_id,
                .output_path = target.output_path,
            });
        }

        slots_.resize(buffer_slot_count_);
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

        if (record_size > kPerFlowBufferSlotSizeBytes) {
            if (!flush_flow_slot(target_index, out_error_text)) {
                return false;
            }
            touch_flow_slot(target_index);
            if (!append_bytes_to_file(state, packet_record_scratch_, out_error_text)) {
                return false;
            }
        } else {
            const auto slot_index = acquire_slot_for_flow(target_index, out_error_text);
            if (!slot_index.has_value()) {
                return false;
            }

            auto& slot = slots_[*slot_index];
            if (slot.used_bytes + record_size > slot.bytes.size()) {
                if (!flush_slot(*slot_index, out_error_text)) {
                    return false;
                }
            }

            std::memcpy(slot.bytes.data() + slot.used_bytes, packet_record_scratch_.data(), record_size);
            slot.used_bytes += record_size;
            slot.last_touch = ++slot_touch_generation_;
        }

        ++state.exported_packet_count;
        state.exported_captured_bytes += packet.captured_length;
        state.exported_original_bytes += packet.original_length;
        ++exported_packets_written_;
        return true;
    }

    bool flush_all(std::string* out_error_text) {
        for (std::size_t slot_index = 0; slot_index < slots_.size(); ++slot_index) {
            if (!flush_slot(slot_index, out_error_text)) {
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
    static constexpr std::size_t kInvalidSlotIndex = std::numeric_limits<std::size_t>::max();

    struct FlowState {
        std::uint32_t export_flow_id {0};
        std::filesystem::path output_path {};
        bool file_initialized {false};
        bool link_type_initialized {false};
        std::uint32_t link_type {kLinkTypeEthernet};
        std::size_t slot_index {kInvalidSlotIndex};
        std::uint64_t exported_packet_count {0};
        std::uint64_t exported_captured_bytes {0};
        std::uint64_t exported_original_bytes {0};
        std::uint64_t last_handle_touch {0};
        bool handle_open {false};
        std::ofstream handle {};
    };

    struct BufferSlot {
        std::array<std::uint8_t, kPerFlowBufferSlotSizeBytes> bytes {};
        std::size_t owner_flow_index {kInvalidSlotIndex};
        std::size_t used_bytes {0};
        std::uint64_t last_touch {0};
    };

    [[nodiscard]] bool flow_has_slot(const std::size_t flow_index) const noexcept {
        return flow_index < states_.size() && states_[flow_index].slot_index != kInvalidSlotIndex;
    }

    void touch_flow_slot(const std::size_t flow_index) {
        if (!flow_has_slot(flow_index)) {
            return;
        }

        auto& slot = slots_[states_[flow_index].slot_index];
        slot.last_touch = ++slot_touch_generation_;
    }

    [[nodiscard]] std::optional<std::size_t> find_free_slot_index() const noexcept {
        for (std::size_t index = 0; index < slots_.size(); ++index) {
            if (slots_[index].owner_flow_index == kInvalidSlotIndex) {
                return index;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::size_t> find_lru_slot_index() const noexcept {
        std::optional<std::size_t> oldest_index {};
        for (std::size_t index = 0; index < slots_.size(); ++index) {
            const auto& slot = slots_[index];
            if (slot.owner_flow_index == kInvalidSlotIndex) {
                continue;
            }

            if (!oldest_index.has_value() || slot.last_touch < slots_[*oldest_index].last_touch) {
                oldest_index = index;
            }
        }
        return oldest_index;
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

    void detach_slot_from_owner(const std::size_t slot_index) {
        auto& slot = slots_[slot_index];
        if (slot.owner_flow_index != kInvalidSlotIndex && slot.owner_flow_index < states_.size()) {
            states_[slot.owner_flow_index].slot_index = kInvalidSlotIndex;
        }
        slot.owner_flow_index = kInvalidSlotIndex;
        slot.used_bytes = 0U;
    }

    bool flush_slot(const std::size_t slot_index, std::string* out_error_text) {
        auto& slot = slots_[slot_index];
        if (slot.used_bytes == 0U) {
            return true;
        }
        if (slot.owner_flow_index == kInvalidSlotIndex || slot.owner_flow_index >= states_.size()) {
            set_error_text(out_error_text, "Internal smart export error: buffer slot owner is invalid.");
            return false;
        }

        auto& state = states_[slot.owner_flow_index];
        if (!append_bytes_to_file(state, std::span<const std::uint8_t>(slot.bytes.data(), slot.used_bytes), out_error_text)) {
            return false;
        }

        slot.used_bytes = 0U;
        return true;
    }

    bool flush_flow_slot(const std::size_t flow_index, std::string* out_error_text) {
        if (!flow_has_slot(flow_index)) {
            return true;
        }

        return flush_slot(states_[flow_index].slot_index, out_error_text);
    }

    [[nodiscard]] std::optional<std::size_t> acquire_slot_for_flow(
        const std::size_t flow_index,
        std::string* out_error_text
    ) {
        if (flow_has_slot(flow_index)) {
            auto& slot = slots_[states_[flow_index].slot_index];
            slot.last_touch = ++slot_touch_generation_;
            return states_[flow_index].slot_index;
        }

        if (const auto free_slot = find_free_slot_index(); free_slot.has_value()) {
            auto& slot = slots_[*free_slot];
            slot.owner_flow_index = flow_index;
            slot.used_bytes = 0U;
            slot.last_touch = ++slot_touch_generation_;
            states_[flow_index].slot_index = *free_slot;
            return *free_slot;
        }

        const auto victim_slot = find_lru_slot_index();
        if (!victim_slot.has_value()) {
            set_error_text(out_error_text, "Internal smart export error: no resident buffer slot is available.");
            return std::nullopt;
        }

        if (!flush_slot(*victim_slot, out_error_text)) {
            return std::nullopt;
        }

        detach_slot_from_owner(*victim_slot);
        auto& slot = slots_[*victim_slot];
        slot.owner_flow_index = flow_index;
        slot.used_bytes = 0U;
        slot.last_touch = ++slot_touch_generation_;
        states_[flow_index].slot_index = *victim_slot;
        return *victim_slot;
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
    std::size_t buffer_slot_count_ {0};
    std::size_t max_open_file_handles_ {0};
    std::vector<FlowState> states_ {};
    std::vector<BufferSlot> slots_ {};
    std::vector<std::uint8_t> packet_record_scratch_ {};
    std::size_t open_handle_count_ {0};
    std::uint64_t slot_touch_generation_ {0};
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
            .phase = PerFlowExportPhase::writing,
            .packets_processed = 0U,
            .total_packets_to_scan = static_cast<std::uint64_t>(total_packets_to_scan),
            .exported_packets_written = 0U,
        });
    }

    auto cancel_export = [&](std::string* error_text) {
        if (!exporter.flush_all(error_text)) {
            return false;
        }
        set_error_text(error_text, "Smart export cancelled by user.");
        return false;
    };

    while (const auto raw_packet = reader.read_next()) {
        const auto processed_packets = raw_packet->packet_index + 1U;
        if (options.cancel_requested &&
            ((processed_packets % kCancellationCheckPacketInterval) == 0U) &&
            options.cancel_requested()) {
            return cancel_export(out_error_text);
        }
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
                        .phase = PerFlowExportPhase::writing,
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
                .phase = PerFlowExportPhase::writing,
                .packets_processed = processed_packets,
                .total_packets_to_scan = static_cast<std::uint64_t>(total_packets_to_scan),
                .exported_packets_written = exporter.exported_packets_written(),
            });
        }
    }

    if (options.cancel_requested && options.cancel_requested()) {
        return cancel_export(out_error_text);
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
            .phase = PerFlowExportPhase::writing,
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
    return export_marked_packets_to_pcap(output_path, packet_selection, source_capture_path, MarkedPacketExportOptions {}, nullptr);
}

bool FlowExportService::export_marked_packets_to_pcap(
    const std::filesystem::path& output_path,
    std::span<const std::uint8_t> packet_selection,
    const std::filesystem::path& source_capture_path,
    const MarkedPacketExportOptions& options,
    std::string* out_error_text
) const {
    if (packet_selection.empty()) {
        set_error_text(out_error_text, "No packets were selected for smart export.");
        return false;
    }

    switch (detect_capture_source_format(source_capture_path)) {
    case CaptureSourceFormat::classic_pcap: {
        PcapReader reader {};
        if (!reader.open(source_capture_path)) {
            set_error_text(out_error_text, reader_failure_text(reader.last_error()));
            return false;
        }

        return export_marked_packets_with_reader(reader, output_path, packet_selection, options, out_error_text);
    }
    case CaptureSourceFormat::pcapng: {
        PcapNgReader reader {};
        if (!reader.open(source_capture_path)) {
            set_error_text(out_error_text, reader_failure_text(reader.last_error()));
            return false;
        }

        return export_marked_packets_with_reader(reader, output_path, packet_selection, options, out_error_text);
    }
    default:
        set_error_text(out_error_text, "Unsupported source capture format for smart export.");
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
