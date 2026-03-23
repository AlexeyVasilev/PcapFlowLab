#include "core/index/CaptureIndexWriter.h"

#include <fstream>

#include "core/index/CaptureIndex.h"
#include "core/index/Serialization.h"

namespace pfl {

bool CaptureIndexWriter::write(const std::filesystem::path& index_path,
                               const CaptureState& state,
                               const std::filesystem::path& source_capture_path) const {
    CaptureSourceInfo source_info {};
    if (!read_capture_source_info(source_capture_path, source_info)) {
        return false;
    }

    std::ofstream stream(index_path, std::ios::binary | std::ios::trunc);
    if (!stream.is_open()) {
        return false;
    }

    if (!detail::write_u64(stream, kCaptureIndexMagic) ||
        !detail::write_u16(stream, kCaptureIndexVersion) ||
        !detail::write_u16(stream, 0U) ||
        !detail::write_capture_source_info(stream, source_info) ||
        !detail::write_capture_state(stream, state)) {
        return false;
    }

    stream.flush();
    return static_cast<bool>(stream);
}

}  // namespace pfl
