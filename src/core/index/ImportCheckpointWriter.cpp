#include "core/index/ImportCheckpointWriter.h"

#include <fstream>

#include "core/index/Serialization.h"

namespace pfl {

bool ImportCheckpointWriter::write(const std::filesystem::path& checkpoint_path,
                                   const ImportCheckpoint& checkpoint) const {
    std::ofstream stream(checkpoint_path, std::ios::binary | std::ios::trunc);
    if (!stream.is_open()) {
        return false;
    }

    if (!detail::write_u64(stream, kImportCheckpointMagic) ||
        !detail::write_u16(stream, kImportCheckpointVersion) ||
        !detail::write_u16(stream, 0U) ||
        !detail::write_capture_source_info(stream, checkpoint.source_info) ||
        !detail::write_u64(stream, checkpoint.packets_processed) ||
        !detail::write_u64(stream, checkpoint.next_input_offset) ||
        !detail::write_u8(stream, checkpoint.completed ? 1U : 0U) ||
        !detail::write_capture_state(stream, checkpoint.state)) {
        return false;
    }

    stream.flush();
    return static_cast<bool>(stream);
}

}  // namespace pfl
