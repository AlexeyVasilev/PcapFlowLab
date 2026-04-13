#pragma once

#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "app/session/FlowRows.h"
#include "core/domain/CaptureState.h"
#include "core/domain/PacketDetails.h"
#include "core/index/CaptureIndex.h"
#include "core/open_failure_info.h"
#include "core/reassembly/ReassemblyTypes.h"
#include "core/services/CaptureImporter.h"
#include "core/services/FlowAnalysisService.h"

struct OpenContext;

namespace pfl {

struct SelectedFlowPacketCacheInfo {
    std::size_t flow_index {0};
    std::size_t cached_packet_window_count {0};
    std::size_t cached_packet_contribution_count {0};
    std::size_t total_cached_bytes {0};
    bool limit_reached {false};
    bool window_fully_cached {false};
};

class CaptureSession {
public:
    bool open_capture(const std::filesystem::path& path);
    bool open_capture(const std::filesystem::path& path, OpenContext* ctx);
    bool open_capture(const std::filesystem::path& path, const CaptureImportOptions& options);
    bool open_capture(const std::filesystem::path& path, const CaptureImportOptions& options, OpenContext* ctx);
    bool open_input(const std::filesystem::path& path);
    bool open_input(const std::filesystem::path& path, OpenContext* ctx);
    bool save_index(const std::filesystem::path& index_path) const;
    bool load_index(const std::filesystem::path& index_path);
    bool load_index(const std::filesystem::path& index_path, OpenContext* ctx);
    [[nodiscard]] bool has_capture() const noexcept;
    [[nodiscard]] bool has_source_capture() const noexcept;
    [[nodiscard]] bool opened_from_index() const noexcept;
    [[nodiscard]] bool is_partial_open() const noexcept;
    [[nodiscard]] const OpenFailureInfo& partial_open_failure() const noexcept;
    [[nodiscard]] const std::string& last_open_error_text() const noexcept;
    bool attach_source_capture(const std::filesystem::path& path);
    [[nodiscard]] const std::filesystem::path& capture_path() const noexcept;
    [[nodiscard]] const std::filesystem::path& attached_source_capture_path() const noexcept;
    [[nodiscard]] const std::filesystem::path& expected_source_capture_path() const noexcept;
    [[nodiscard]] const CaptureSummary& summary() const noexcept;
    [[nodiscard]] CaptureProtocolSummary protocol_summary() const noexcept;
    void set_analysis_settings(const AnalysisSettings& settings) noexcept;
    [[nodiscard]] CaptureTopSummary top_summary(std::size_t limit = 5) const;
    [[nodiscard]] QuicRecognitionStats quic_recognition_stats() const noexcept;
    [[nodiscard]] TlsRecognitionStats tls_recognition_stats() const noexcept;
    [[nodiscard]] std::vector<std::uint8_t> read_packet_data(const PacketRef& packet) const;
    [[nodiscard]] std::optional<PacketDetails> read_packet_details(const PacketRef& packet) const;
    [[nodiscard]] std::string read_packet_hex_dump(const PacketRef& packet) const;
    [[nodiscard]] std::string read_packet_payload_hex_dump(const PacketRef& packet) const;
    [[nodiscard]] std::string read_packet_protocol_details_text(const PacketRef& packet) const;
    [[nodiscard]] std::optional<ReassemblyResult> reassemble_flow_direction(const ReassemblyRequest& request) const;
    [[nodiscard]] std::vector<FlowRow> list_flows() const;
    [[nodiscard]] std::optional<FlowAnalysisResult> get_flow_analysis(std::size_t flow_index) const;
    [[nodiscard]] std::optional<std::string> derive_quic_service_hint_for_flow(std::size_t flow_index) const;
    [[nodiscard]] std::optional<std::string> derive_quic_protocol_text_for_packet(std::size_t flow_index, std::uint64_t packet_index) const;
    [[nodiscard]] std::optional<std::string> derive_quic_protocol_text_for_packet_context(
        std::size_t flow_index,
        const std::vector<std::uint64_t>& packet_indices
    ) const;
    [[nodiscard]] std::optional<std::string> derive_quic_protocol_details_for_packet(std::size_t flow_index, std::uint64_t packet_index) const;
    [[nodiscard]] std::optional<std::string> derive_quic_protocol_details_for_packet_context(
        std::size_t flow_index,
        const std::vector<std::uint64_t>& packet_indices
    ) const;
    [[nodiscard]] std::vector<PacketRow> list_flow_packets(std::size_t flow_index) const;
    [[nodiscard]] std::vector<PacketRow> list_flow_packets(std::size_t flow_index, std::size_t offset, std::size_t limit) const;
    [[nodiscard]] std::vector<std::uint64_t> suspected_tcp_retransmission_packet_indices(std::size_t flow_index) const;
    [[nodiscard]] std::vector<std::uint64_t> suspected_tcp_retransmission_packet_indices(std::size_t flow_index, std::size_t max_packets_to_scan) const;
    void prepare_selected_flow_packet_cache(std::size_t flow_index, std::size_t max_packets_to_scan) const;
    void clear_selected_flow_packet_cache() noexcept;
    [[nodiscard]] std::optional<SelectedFlowPacketCacheInfo> selected_flow_packet_cache_info() const noexcept;
    [[nodiscard]] bool selected_flow_packet_cache_limit_reached() const noexcept;
    [[nodiscard]] std::vector<std::uint8_t> read_selected_flow_transport_payload(std::size_t flow_index, const PacketRef& packet) const;
    void set_selected_flow_tcp_payload_suppression(std::size_t flow_index, const std::vector<std::uint64_t>& packet_indices) noexcept;
    void set_selected_flow_tcp_payload_suppression(std::size_t flow_index, const std::vector<std::uint64_t>& packet_indices, std::size_t max_packets_to_scan) noexcept;
    void clear_selected_flow_tcp_payload_suppression() noexcept;
    [[nodiscard]] bool should_suppress_selected_flow_tcp_payload(std::size_t flow_index, std::uint64_t packet_index) const noexcept;
    [[nodiscard]] std::size_t selected_flow_tcp_payload_trim_prefix_bytes(std::size_t flow_index, std::uint64_t packet_index) const noexcept;
    [[nodiscard]] bool selected_flow_tcp_direction_tainted_by_gap(std::size_t flow_index, Direction direction) const noexcept;
    [[nodiscard]] std::optional<std::uint64_t> selected_flow_tcp_direction_first_gap_packet_index(std::size_t flow_index, Direction direction) const noexcept;
    [[nodiscard]] std::size_t flow_packet_count(std::size_t flow_index) const noexcept;
    [[nodiscard]] std::vector<StreamItemRow> list_flow_stream_items(std::size_t flow_index) const;
    [[nodiscard]] std::vector<StreamItemRow> list_flow_stream_items(std::size_t flow_index, std::size_t offset, std::size_t limit) const;
    [[nodiscard]] std::vector<StreamItemRow> list_flow_stream_items_for_packet_prefix(std::size_t flow_index, std::size_t max_packets_to_scan, std::size_t limit) const;
    [[nodiscard]] std::size_t flow_stream_item_count(std::size_t flow_index) const;
    [[nodiscard]] std::optional<std::vector<PacketRef>> flow_packets(std::size_t flow_index) const;
    bool export_flow_to_pcap(std::size_t flow_index, const std::filesystem::path& output_path) const;
    bool export_flows_to_pcap(const std::vector<std::size_t>& flow_indices, const std::filesystem::path& output_path) const;
    [[nodiscard]] std::optional<PacketRef> find_packet(std::uint64_t packet_index) const;
    [[nodiscard]] CaptureState& state() noexcept;
    [[nodiscard]] const CaptureState& state() const noexcept;

private:
    struct SelectedFlowTcpPayloadContribution {
        bool suppress_entire_packet {false};
        std::size_t trim_prefix_bytes {0};
    };

    struct SelectedFlowTcpDirectionalGapState {
        bool tainted_by_gap {false};
        std::uint64_t first_gap_packet_index {0};
    };

    struct SelectedFlowTcpPayloadSuppression {
        std::size_t flow_index {0};
        std::map<std::uint64_t, SelectedFlowTcpPayloadContribution> packet_contributions {};
        SelectedFlowTcpDirectionalGapState gap_state_a_to_b {};
        SelectedFlowTcpDirectionalGapState gap_state_b_to_a {};
    };

    struct SelectedFlowPacketCacheEntry {
        std::uint64_t flow_local_packet_number {0};
        std::uint64_t packet_index {0};
        Direction direction {Direction::a_to_b};
        std::size_t cache_offset {0};
        std::size_t cache_length {0};
        std::uint32_t payload_length {0};
        bool payload_cached {false};
    };

    struct SelectedFlowPacketCache {
        std::size_t flow_index {0};
        std::vector<std::uint8_t> bytes {};
        std::vector<SelectedFlowPacketCacheEntry> entries {};
        std::map<std::uint64_t, std::size_t> entry_index_by_packet_index {};
        std::size_t cached_packet_window_count {0};
        bool limit_reached {false};
        bool has_uncached_payload_entries {false};
        bool window_fully_cached {false};
    };

    [[nodiscard]] std::vector<std::uint8_t> read_transport_payload_direct(const PacketRef& packet) const;
    [[nodiscard]] const SelectedFlowPacketCacheEntry* find_selected_flow_packet_cache_entry(
        std::size_t flow_index,
        std::uint64_t packet_index
    ) const noexcept;

    void reset_runtime_state() noexcept;

    std::filesystem::path capture_path_ {};
    std::filesystem::path source_capture_path_ {};
    CaptureSourceInfo source_info_ {};
    CaptureState state_ {};
    ImportMode import_mode_ {ImportMode::fast};
    AnalysisSettings analysis_settings_ {};
    bool deep_protocol_details_enabled_ {false};
    bool opened_from_index_ {false};
    bool has_loaded_state_ {false};
    bool partial_open_ {false};
    OpenFailureInfo partial_open_failure_ {};
    std::string last_open_error_text_ {};
    mutable std::optional<SelectedFlowPacketCache> selected_flow_packet_cache_ {};
    std::optional<SelectedFlowTcpPayloadSuppression> selected_flow_tcp_payload_suppression_ {};
};

}  // namespace pfl









