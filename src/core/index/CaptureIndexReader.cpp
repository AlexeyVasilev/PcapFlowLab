#include "core/index/CaptureIndexReader.h"

#include <fstream>

#include "core/index/Serialization.h"

namespace pfl {

bool CaptureIndexReader::read(const std::filesystem::path& index_path,
                              CaptureState& out_state,
                              std::filesystem::path& out_source_capture_path,
                              CaptureSourceInfo* out_source_info) const {
    out_state = {};
    out_source_capture_path.clear();
    if (out_source_info != nullptr) {
        *out_source_info = {};
    }

    std::ifstream stream(index_path, std::ios::binary);
    if (!stream.is_open()) {
        return false;
    }

    std::uint64_t magic {0};
    std::uint16_t version {0};
    std::uint16_t reserved {0};
    CaptureSourceInfo source_info {};

    if (!detail::read_u64(stream, magic) ||
        !detail::read_u16(stream, version) ||
        !detail::read_u16(stream, reserved) ||
        magic != kCaptureIndexMagic ||
        version != kCaptureIndexVersion ||
        !detail::read_capture_source_info(stream, source_info) ||
        !detail::read_capture_state(stream, out_state)) {
        out_state = {};
        return false;
    }

    out_source_capture_path = source_info.capture_path;
    if (out_source_info != nullptr) {
        *out_source_info = source_info;
    }

    return true;
}

}  // namespace pfl
