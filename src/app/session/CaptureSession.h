#pragma once

#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>
#include <array>

#include "app/session/FlowRows.h"
#include "app/session/SessionFlowHelpers.h"
#include "core/domain/CaptureState.h"
#include "core/domain/PacketDetails.h"
#include "core/index/CaptureIndex.h"
#include "core/index/CaptureIndexWriter.h"
#include "core/open_failure_info.h"
#include "core/reassembly/ReassemblyTypes.h"
#include "core/services/CaptureImporter.h"
#include "core/services/FlowExportService.h"
#include "core/services/FlowAnalysisService.h"

struct OpenContext;

namespace pfl {

enum class SmartFlowExportBaseMode : std::uint8_t {
    all_packets = 0,
    first_n_packets = 1,
    first_m_original_bytes = 2,
};

struct SmartPacketRetentionOptions {
    SmartFlowExportBaseMode base_mode {SmartFlowExportBaseMode::all_packets};
    std::uint64_t first_n_packets {0};
    std::uint64_t first_m_original_bytes {0};
    bool include_last_packet {false};
    bool include_every_kth_packet_after_base {false};
    std::uint64_t every_kth_packet {0};
};

struct SmartFlowExportRequest {
    std::vector<std::size_t> flow_indices {};
    SmartFlowExportBaseMode base_mode {SmartFlowExportBaseMode::all_packets};
    std::uint64_t first_n_packets {0};
    std::uint64_t first_m_original_bytes {0};
    bool include_last_packet {false};
    bool include_every_kth_packet_after_base {false};
    std::uint64_t every_kth_packet {0};
};

struct SmartPacketListExportRequest {
    std::vector<std::size_t> packet_indices {};
    SmartPacketRetentionOptions retention {};
};

enum class SmartPerFlowExportPhase {
    preparing,
    writing,
};

struct SmartPerFlowExportProgress {
    SmartPerFlowExportPhase phase {SmartPerFlowExportPhase::preparing};
    std::uint64_t packets_processed {0};
    std::uint64_t total_packets_to_scan {0};
    std::uint64_t exported_packets_written {0};
};

using SmartPerFlowExportProgressCallback = std::function<void(const SmartPerFlowExportProgress&)>;

struct SmartPerFlowExportOptions {
    std::size_t buffer_budget_bytes {128U * 1024U * 1024U};
    SmartPerFlowExportProgressCallback progress_callback {};
    std::function<bool()> cancel_requested {};
};

using SmartSingleFileExportProgress = MarkedPacketExportProgress;
using SmartSingleFileExportProgressCallback = MarkedPacketExportProgressCallback;
using SmartSingleFileExportOptions = MarkedPacketExportOptions;
using IndexSaveProgress = CaptureIndexWriteProgress;
using IndexSaveProgressCallback = CaptureIndexWriteProgressCallback;
using IndexSaveOptions = CaptureIndexWriteOptions;

struct SelectedFlowPacketCacheInfo {
    std::size_t flow_index {0};
    std::size_t cached_packet_window_count {0};
    std::size_t cached_packet_contribution_count {0};
    std::size_t total_cached_bytes {0};
    bool limit_reached {false};
    bool window_fully_cached {false};
};

struct CaptureStorageSummary {
    std::uint64_t total_packets_seen {0};
    std::uint64_t recognized_packets {0};
    std::uint64_t unrecognized_packets {0};
    std::uint64_t ipv4_connection_count {0};
    std::uint64_t ipv6_connection_count {0};
    std::uint64_t flow_count {0};
    std::uint64_t connection_packet_refs {0};
    std::uint64_t unrecognized_packet_refs {0};
    std::uint64_t unique_protocol_paths {0};
    std::uint64_t protocol_path_layers_total {0};
    std::uint64_t protocol_path_max_depth {0};
    std::uint64_t sizeof_packet_ref {0};
    std::uint64_t sizeof_unrecognized_packet_record {0};
    std::uint64_t sizeof_layer_key {0};
    std::uint64_t approx_connection_packet_ref_bytes {0};
    std::uint64_t approx_unrecognized_record_bytes {0};
    std::uint64_t approx_unrecognized_reason_text_bytes {0};
    std::uint64_t approx_protocol_path_layer_payload_bytes {0};
};

class CaptureSession {
public:
    using IndexSaveProgress = pfl::IndexSaveProgress;
    using IndexSaveProgressCallback = pfl::IndexSaveProgressCallback;
    using IndexSaveOptions = pfl::IndexSaveOptions;

    CaptureSession() = default;
    CaptureSession(CaptureSession&& other) noexcept;
    CaptureSession& operator=(CaptureSession&& other) noexcept;

    bool open_capture(const std::filesystem::path& path);
    bool open_capture(const std::filesystem::path& path, OpenContext* ctx);
    bool open_capture(const std::filesystem::path& path, const CaptureImportOptions& options);
    bool open_capture(const std::filesystem::path& path, const CaptureImportOptions& options, OpenContext* ctx);
    bool open_input(const std::filesystem::path& path);
    bool open_input(const std::filesystem::path& path, OpenContext* ctx);
    bool save_index(const std::filesystem::path& index_path) const;
    bool save_index(
        const std::filesystem::path& index_path,
        const IndexSaveOptions& options,
        std::string* out_error_text
    ) const;
    bool load_index(const std::filesystem::path& index_path);
    bool load_index(const std::filesystem::path& index_path, OpenContext* ctx);
    [[nodiscard]] bool has_capture() const noexcept;
    [[nodiscard]] bool has_source_capture() const noexcept;
    [[nodiscard]] bool source_capture_accessible() const noexcept;
    [[nodiscard]] bool opened_from_index() const noexcept;
    [[nodiscard]] bool is_partial_open() const noexcept;
    [[nodiscard]] const OpenFailureInfo& partial_open_failure() const noexcept;
    [[nodiscard]] const std::string& last_open_error_text() const noexcept;
    bool attach_source_capture(const std::filesystem::path& path);
    void clear_source_capture_attachment() noexcept;
    [[nodiscard]] const std::filesystem::path& capture_path() const noexcept;
    [[nodiscard]] const std::filesystem::path& attached_source_capture_path() const noexcept;
    [[nodiscard]] const std::filesystem::path& expected_source_capture_path() const noexcept;
    [[nodiscard]] const CaptureSummary& summary() const noexcept;
    [[nodiscard]] CaptureProtocolSummary protocol_summary() const noexcept;
    [[nodiscard]] CaptureProtocolPathSummary protocol_path_summary(
        ProtocolPathStatisticsMode mode = ProtocolPathStatisticsMode::kind_overview
    ) const;
    [[nodiscard]] std::vector<FlowIndex> protocol_path_summary_flow_indices(
        ProtocolPathStatisticsMode mode,
        std::uint64_t node_id
    ) const;
    void clear_runtime_caches_after_transfer() noexcept;
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
    [[nodiscard]] std::optional<ReassemblyResult> reassemble_flow_direction(
        const ReassemblyRequest& request,
        std::span<const PacketRef> direction_packets
    ) const;
    [[nodiscard]] std::vector<FlowRow> list_flows() const;
    [[nodiscard]] std::optional<FlowRow> flow_row(std::size_t flow_index) const;
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
    [[nodiscard]] std::vector<UnrecognizedPacketRow> list_unrecognized_packets() const;
    [[nodiscard]] std::vector<UnrecognizedPacketRow> list_unrecognized_packets(std::size_t offset, std::size_t limit) const;
    [[nodiscard]] std::vector<std::uint64_t> suspected_tcp_retransmission_packet_indices(std::size_t flow_index) const;
    [[nodiscard]] std::vector<std::uint64_t> suspected_tcp_retransmission_packet_indices(std::size_t flow_index, std::size_t max_packets_to_scan) const;
    void prepare_selected_flow_packet_cache(std::size_t flow_index, std::size_t max_packets_to_scan) const;
    void clear_selected_flow_packet_cache() noexcept;
    [[nodiscard]] std::optional<SelectedFlowPacketCacheInfo> selected_flow_packet_cache_info() const noexcept;
    [[nodiscard]] bool selected_flow_packet_cache_limit_reached() const noexcept;
    [[nodiscard]] std::optional<std::uint64_t> selected_flow_cached_packet_number(
        std::size_t flow_index,
        std::uint64_t packet_index
    ) const noexcept;
    [[nodiscard]] std::vector<std::uint8_t> read_selected_flow_transport_payload(std::size_t flow_index, const PacketRef& packet) const;
    [[nodiscard]] std::vector<std::uint8_t> read_selected_flow_transport_payload_prefix(
        std::size_t flow_index,
        const PacketRef& packet,
        std::size_t max_bytes
    ) const;
    [[nodiscard]] std::vector<std::uint8_t> read_selected_flow_transport_payload_slice(
        std::size_t flow_index,
        const PacketRef& packet,
        std::size_t payload_offset,
        std::size_t max_bytes
    ) const;
    void set_selected_flow_tcp_payload_suppression(std::size_t flow_index, const std::vector<std::uint64_t>& packet_indices) noexcept;
    void set_selected_flow_tcp_payload_suppression(std::size_t flow_index, const std::vector<std::uint64_t>& packet_indices, std::size_t max_packets_to_scan) noexcept;
    void clear_selected_flow_tcp_payload_suppression() noexcept;
    [[nodiscard]] bool should_suppress_selected_flow_tcp_payload(std::size_t flow_index, std::uint64_t packet_index) const noexcept;
    [[nodiscard]] std::size_t selected_flow_tcp_payload_trim_prefix_bytes(std::size_t flow_index, std::uint64_t packet_index) const noexcept;
    [[nodiscard]] bool selected_flow_tcp_direction_tainted_by_gap(std::size_t flow_index, Direction direction) const noexcept;
    [[nodiscard]] std::optional<std::uint64_t> selected_flow_tcp_direction_first_gap_packet_index(std::size_t flow_index, Direction direction) const noexcept;
    [[nodiscard]] std::size_t flow_packet_count(std::size_t flow_index) const noexcept;
    [[nodiscard]] std::size_t unrecognized_packet_count() const noexcept;
    [[nodiscard]] UnrecognizedPacketStatistics unrecognized_packet_statistics() const noexcept;
    [[nodiscard]] std::vector<StreamItemRow> list_flow_stream_items(std::size_t flow_index) const;
    [[nodiscard]] std::vector<StreamItemRow> list_flow_stream_items(std::size_t flow_index, std::size_t offset, std::size_t limit) const;
    [[nodiscard]] std::vector<StreamItemRow> list_flow_stream_items_for_packet_prefix(std::size_t flow_index, std::size_t max_packets_to_scan, std::size_t limit) const;
    [[nodiscard]] std::size_t flow_stream_item_count(std::size_t flow_index) const;
    [[nodiscard]] std::optional<std::vector<PacketRef>> flow_packets(std::size_t flow_index) const;
    [[nodiscard]] std::optional<PacketRef> selected_flow_packet_at(std::size_t flow_index, std::uint64_t flow_packet_index) const;
    [[nodiscard]] std::optional<std::uint64_t> selected_flow_packet_number(std::size_t flow_index, std::uint64_t packet_index) const;
    [[nodiscard]] std::optional<std::uint64_t> selected_flow_exact_packet_number(
        std::size_t flow_index,
        std::uint64_t packet_index
    ) const;
    bool export_flow_to_pcap(std::size_t flow_index, const std::filesystem::path& output_path) const;
    bool export_flows_to_pcap(const std::vector<std::size_t>& flow_indices, const std::filesystem::path& output_path) const;
    bool export_smart_flows_to_pcap(const SmartFlowExportRequest& request, const std::filesystem::path& output_path) const;
    bool export_smart_flows_to_pcap(
        const SmartFlowExportRequest& request,
        const std::filesystem::path& output_path,
        const SmartSingleFileExportOptions& options,
        std::string* out_error_text
    ) const;
    bool export_smart_packets_to_pcap(
        const SmartPacketListExportRequest& request,
        const std::filesystem::path& output_path
    ) const;
    bool export_smart_unrecognized_packets_to_pcap(
        const SmartPacketRetentionOptions& options,
        const std::filesystem::path& output_path
    ) const;
    bool export_smart_unrecognized_packets_to_pcap(
        const SmartPacketRetentionOptions& options,
        const std::filesystem::path& output_path,
        const SmartSingleFileExportOptions& export_options,
        std::string* out_error_text
    ) const;
    bool export_smart_flows_to_folder(const SmartFlowExportRequest& request, const std::filesystem::path& output_directory) const;
    bool export_smart_flows_to_folder(
        const SmartFlowExportRequest& request,
        const std::filesystem::path& output_directory,
        const SmartPerFlowExportOptions& options,
        std::string* out_error_text
    ) const;
    bool export_all_flows_info_csv(const std::filesystem::path& output_path) const;
    bool export_all_flows_info_csv(const std::filesystem::path& output_path, std::string* out_error_text) const;
    [[nodiscard]] std::optional<PacketRef> find_packet(std::uint64_t packet_index) const;
    [[nodiscard]] CaptureStorageSummary storage_summary() const;
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
        PacketRef packet {};
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

    struct SelectedFlowTcpPrefixWindowPacket {
        PacketRef packet {};
        Direction direction {Direction::a_to_b};
        std::uint64_t flow_local_packet_number {0};
    };

    struct SelectedFlowTcpPrefixContext {
        std::size_t flow_index {0};
        std::size_t prepared_packet_window_count {0};
        FlowAddressFamily family {FlowAddressFamily::ipv4};
        const ConnectionV4* ipv4 {nullptr};
        const ConnectionV6* ipv6 {nullptr};
        std::size_t prefix_count_a {0};
        std::size_t prefix_count_b {0};
        std::size_t payload_packet_count {0};
        std::vector<PacketRef> prefix_packets_a {};
        std::vector<PacketRef> prefix_packets_b {};
        std::vector<SelectedFlowTcpPrefixWindowPacket> ordered_prefix_packets {};
    };

    struct SelectedFlowTcpPrefixResolution {
        const SelectedFlowTcpPrefixContext* context {nullptr};
        const char* result {"invalid"};
        bool reused_existing_context {false};
        bool listed_connections_called {false};
        bool listed_connections_cache_hit {false};
    };

    struct SelectedFlowFullPacketCache {
        std::size_t flow_index {0};
        std::map<std::uint64_t, std::vector<std::uint8_t>> packet_bytes_by_packet_index {};
        std::size_t total_cached_bytes {0};
        bool limit_reached {false};
    };

    [[nodiscard]] std::vector<std::uint8_t> read_transport_payload_direct(const PacketRef& packet) const;
    void prepare_selected_flow_full_packet_cache(std::size_t flow_index, std::span<const PacketRef> packets) const;
    [[nodiscard]] SelectedFlowTcpPrefixResolution prepare_selected_flow_tcp_prefix_context(
        std::size_t flow_index,
        std::size_t max_packets_to_scan
    ) const;
    [[nodiscard]] const std::vector<std::uint8_t>* find_selected_flow_full_packet_cache_bytes(std::uint64_t packet_index) const noexcept;
    [[nodiscard]] const SelectedFlowPacketCacheEntry* find_selected_flow_packet_cache_entry(
        std::size_t flow_index,
        std::uint64_t packet_index
    ) const noexcept;
    [[nodiscard]] const std::vector<session_detail::ListedConnectionRef>& listed_connections(bool* cache_hit = nullptr) const;
    void prepare_selected_flow_packet_cache(std::size_t flow_index, const SelectedFlowTcpPrefixContext& context) const;
    [[nodiscard]] std::optional<PacketRef> selected_flow_cached_packet_at(
        std::size_t flow_index,
        std::uint64_t flow_packet_index
    ) const noexcept;

    void swap(CaptureSession& other) noexcept;
    void reset_runtime_state() noexcept;

    std::filesystem::path capture_path_ {};
    std::filesystem::path source_capture_path_ {};
    CaptureSourceInfo source_info_ {};
    CaptureState state_ {};
    AnalysisSettings analysis_settings_ {};
    bool opened_from_index_ {false};
    bool has_loaded_state_ {false};
    bool partial_open_ {false};
    OpenFailureInfo partial_open_failure_ {};
    std::string last_open_error_text_ {};
    mutable std::optional<SelectedFlowFullPacketCache> selected_flow_full_packet_cache_ {};
    mutable std::optional<SelectedFlowPacketCache> selected_flow_packet_cache_ {};
    mutable std::optional<SelectedFlowTcpPrefixContext> selected_flow_tcp_prefix_context_ {};
    mutable std::optional<std::vector<session_detail::ListedConnectionRef>> listed_connections_cache_ {};
    mutable std::array<std::optional<CaptureProtocolPathSummary>, 3> protocol_path_summary_cache_ {};
    std::optional<SelectedFlowTcpPayloadSuppression> selected_flow_tcp_payload_suppression_ {};
};

}  // namespace pfl









