#pragma once

#include <cstddef>
#include <filesystem>

#include "core/dissection/CommonDirectDissection.h"
#include "core/domain/CaptureState.h"
#include "core/io/PcapNgReader.h"
#include "core/io/PcapReader.h"
#include "core/services/AnalysisSettings.h"
#include "core/services/CaptureImporter.h"
#include "core/services/FlowHintService.h"

struct OpenContext;

namespace pfl {

enum class ClassicImportPacketDisposition {
    continue_after_packet = 0,
    stop_after_packet,
    failure_before_packet_surfaced,
};

class CaptureImportProcessor {
public:
    explicit CaptureImportProcessor(AnalysisSettings settings = {});

    void process_packet(RawPcapPacket& packet, CaptureState& state) const;
    [[nodiscard]] ClassicImportPacketDisposition process_classic_import_packet(
        PcapReader& reader,
        RawPcapPacket& packet,
        CaptureState& state,
        std::size_t& adaptive_header_prefix_bytes
    ) const;

private:
    const dissection::DissectionRegistry* registry_ {nullptr};
    FlowHintService hint_service_ {};
};

[[nodiscard]] CaptureImportResult import_capture_from_reader(PcapReader& reader, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx = nullptr);
[[nodiscard]] CaptureImportResult import_capture_from_reader(PcapNgReader& reader, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx = nullptr);
[[nodiscard]] CaptureImportResult import_capture_from_path(const std::filesystem::path& path, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx = nullptr);

}  // namespace pfl
