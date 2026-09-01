#pragma once

#include <filesystem>

#include "core/domain/CaptureState.h"
#include "core/index/CaptureIndex.h"
#include "core/index/Serialization.h"
#include "core/open_failure_info.h"

struct OpenContext;

namespace pfl {

class CaptureIndexReader {
public:
    bool inspect(const std::filesystem::path& index_path,
                 CaptureIndexInspection& out_inspection,
                 OpenContext* ctx = nullptr) const;
    bool read(const std::filesystem::path& index_path,
              CaptureState& out_state,
              std::filesystem::path& out_source_capture_path,
              CaptureSourceInfo* out_source_info = nullptr,
              OpenContext* ctx = nullptr) const;
    bool read_v16_complete(const std::filesystem::path& index_path,
                           detail::CaptureIndexV16CompleteReadResult& out_result,
                           OpenContext* ctx = nullptr) const;
    bool read_v16_fast_statistics(const std::filesystem::path& index_path,
                                  detail::CaptureIndexV16FastStatisticsTier& out_tier,
                                  detail::CaptureIndexV16FastStatisticsTierReadResult& out_result,
                                  OpenContext* ctx = nullptr) const;
    [[nodiscard]] const OpenFailureInfo& last_error() const noexcept;

private:
    void clear_error() const;
    void set_error_context(std::uint64_t file_offset, const char* reason) const;
    void set_error_context(const char* reason) const;

    mutable OpenFailureInfo last_error_ {};
};

}  // namespace pfl

