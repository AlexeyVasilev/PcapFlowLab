#include "core/index/ImportCheckpointReader.h"

#include <fstream>

#include "core/index/Serialization.h"

namespace pfl {

bool ImportCheckpointReader::read(const std::filesystem::path& checkpoint_path,
                                  ImportCheckpoint& out_checkpoint) const {
    out_checkpoint = {};

    std::ifstream stream(checkpoint_path, std::ios::binary);
    if (!stream.is_open()) {
        return false;
    }

    std::uint64_t magic {0};
    std::uint16_t version {0};
    std::uint16_t reserved {0};
    std::uint8_t completed {0};

    if (!detail::read_u64(stream, magic) ||
        !detail::read_u16(stream, version) ||
        !detail::read_u16(stream, reserved) ||
        magic != kImportCheckpointMagic ||
        version != kImportCheckpointVersion ||
        !detail::read_capture_source_info(stream, out_checkpoint.source_info) ||
        !detail::read_u64(stream, out_checkpoint.packets_processed) ||
        !detail::read_u64(stream, out_checkpoint.next_input_offset) ||
        !detail::read_u8(stream, completed) ||
        !detail::read_capture_state(stream, out_checkpoint.state)) {
        out_checkpoint = {};
        return false;
    }

    out_checkpoint.completed = completed != 0;
    return true;
}

}  // namespace pfl
