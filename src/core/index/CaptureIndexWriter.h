#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>

#include "core/domain/CaptureState.h"
#include "core/index/CaptureIndex.h"
#include "core/index/CaptureIndexV16.h"
#include "core/index/Serialization.h"

namespace pfl {

enum class CaptureIndexWritePhase {
    preparing,
    writing,
    finalizing,
    replacing_target,
};

struct CaptureIndexWriteProgress {
    CaptureIndexWritePhase phase {CaptureIndexWritePhase::preparing};
    std::string phase_text {};
    std::uint64_t completed_sections {0};
    std::uint64_t total_sections {0};
    std::uint64_t phase_items_processed {0};
    std::uint64_t phase_items_total {0};
    std::uint64_t bytes_written {0};
};

using CaptureIndexWriteProgressCallback = std::function<void(const CaptureIndexWriteProgress&)>;

struct CaptureIndexWriteOptions {
    CaptureIndexWriteProgressCallback progress_callback {};
    std::function<bool()> cancel_requested {};
    std::uint64_t max_connection_section_payload_bytes {128U * 1024U * 1024U};
};

class CaptureIndexWriter {
public:
    bool write(const std::filesystem::path& index_path,
               const CaptureState& state,
               const std::filesystem::path& source_capture_path) const;
    bool write(const std::filesystem::path& index_path,
               const CaptureState& state,
               const std::filesystem::path& source_capture_path,
               const CaptureIndexWriteOptions& options,
               std::string* out_error_text) const;
    bool write_v16(const std::filesystem::path& index_path,
                   const CaptureSourceInfo& source_info,
                   const detail::CaptureIndexV16FastStatisticsTier& fast_tier,
                   const CaptureIndexV16WritePlan& plan,
                   const CaptureIndexWriteOptions& options,
                   std::string* out_error_text) const;
    bool rewrite_v16_with_source_header(const std::filesystem::path& index_path,
                                        const std::filesystem::path& existing_index_path,
                                        const CaptureSourceInfo& source_info,
                                        const CaptureIndexWriteOptions& options,
                                        std::string* out_error_text) const;
};

}  // namespace pfl
