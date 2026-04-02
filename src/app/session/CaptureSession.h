#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "app/session/FlowRows.h"
#include "core/domain/CaptureState.h"
#include "core/domain/PacketDetails.h"
#include "core/index/CaptureIndex.h"
#include "core/open_failure_info.h"
#include "core/reassembly/ReassemblyTypes.h"
#include "core/services/CaptureImporter.h"

struct OpenContext;

namespace pfl {

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
    [[nodiscard]] const CaptureSummary& summary() const noexcept;
    [[nodiscard]] CaptureProtocolSummary protocol_summary() const noexcept;
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
    [[nodiscard]] std::optional<std::string> derive_quic_service_hint_for_flow(std::size_t flow_index) const;
    [[nodiscard]] std::vector<PacketRow> list_flow_packets(std::size_t flow_index) const;
    [[nodiscard]] std::vector<PacketRow> list_flow_packets(std::size_t flow_index, std::size_t offset, std::size_t limit) const;
    [[nodiscard]] std::size_t flow_packet_count(std::size_t flow_index) const noexcept;
    [[nodiscard]] std::vector<StreamItemRow> list_flow_stream_items(std::size_t flow_index) const;
    [[nodiscard]] std::vector<StreamItemRow> list_flow_stream_items(std::size_t flow_index, std::size_t offset, std::size_t limit) const;
    [[nodiscard]] std::vector<StreamItemRow> list_flow_stream_items_for_packet_prefix(std::size_t flow_index, std::size_t max_packets_to_scan, std::size_t limit) const;
    [[nodiscard]] std::size_t flow_stream_item_count(std::size_t flow_index) const;
    [[nodiscard]] std::optional<std::vector<PacketRef>> flow_packets(std::size_t flow_index) const;
    bool export_flow_to_pcap(std::size_t flow_index, const std::filesystem::path& output_path) const;
    [[nodiscard]] std::optional<PacketRef> find_packet(std::uint64_t packet_index) const;
    [[nodiscard]] CaptureState& state() noexcept;
    [[nodiscard]] const CaptureState& state() const noexcept;

private:
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
};

}  // namespace pfl

