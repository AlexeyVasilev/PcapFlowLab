#pragma once

#include <filesystem>

#include "core/decode/PacketDecoder.h"
#include "core/domain/CaptureState.h"
#include "core/io/PcapNgReader.h"
#include "core/io/PcapReader.h"
#include "core/services/AnalysisSettings.h"
#include "core/services/CaptureImporter.h"
#include "core/services/FlowHintService.h"

struct OpenContext;

namespace pfl {

class CaptureImportProcessor {
public:
    explicit CaptureImportProcessor(AnalysisSettings settings = {});

    void process_packet(const RawPcapPacket& packet, CaptureState& state) const;

private:
    PacketDecoder decoder_ {};
    FlowHintService hint_service_ {};
};

[[nodiscard]] CaptureImportResult import_capture_from_reader(PcapReader& reader, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx = nullptr);
[[nodiscard]] CaptureImportResult import_capture_from_reader(PcapNgReader& reader, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx = nullptr);
[[nodiscard]] CaptureImportResult import_capture_from_path(const std::filesystem::path& path, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx = nullptr);

}  // namespace pfl
