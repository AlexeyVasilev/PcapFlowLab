#include "core/index/ImportCheckpointWriter.h"

#include <fstream>
#include <sstream>
#include <string>

#include "core/index/Serialization.h"

namespace pfl {

namespace {

template <typename Writer>
bool write_marshaled_section(std::ofstream& stream, const detail::ImportCheckpointSectionId section_id, Writer&& writer) {
    std::ostringstream payload_stream(std::ios::out | std::ios::binary);
    if (!writer(payload_stream)) {
        return false;
    }

    const std::string payload = payload_stream.str();
    const auto bytes = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(payload.data()),
        payload.size()
    );
    return detail::write_section(stream, static_cast<std::uint32_t>(section_id), bytes);
}

}  // namespace

bool ImportCheckpointWriter::write(const std::filesystem::path& checkpoint_path,
                                   const ImportCheckpoint& checkpoint) const {
    std::ofstream stream(checkpoint_path, std::ios::binary | std::ios::trunc);
    if (!stream.is_open()) {
        return false;
    }

    if (!detail::write_u64(stream, kImportCheckpointMagic) ||
        !detail::write_u16(stream, kImportCheckpointVersion) ||
        !detail::write_u16(stream, 0U) ||
        !write_marshaled_section(stream, detail::ImportCheckpointSectionId::source_info, [&](std::ostream& payload) {
            return detail::write_capture_source_info(payload, checkpoint.source_info);
        }) ||
        !write_marshaled_section(stream, detail::ImportCheckpointSectionId::progress, [&](std::ostream& payload) {
            return detail::write_u64(payload, checkpoint.packets_processed) &&
                   detail::write_u64(payload, checkpoint.next_input_offset) &&
                   detail::write_u8(payload, checkpoint.completed ? 1U : 0U);
        }) ||
        !write_marshaled_section(stream, detail::ImportCheckpointSectionId::summary, [&](std::ostream& payload) {
            return detail::write_capture_summary(payload, checkpoint.state.summary);
        }) ||
        !write_marshaled_section(stream, detail::ImportCheckpointSectionId::ipv4_connections, [&](std::ostream& payload) {
            return detail::write_connection_table(payload, checkpoint.state.ipv4_connections);
        }) ||
        !write_marshaled_section(stream, detail::ImportCheckpointSectionId::ipv6_connections, [&](std::ostream& payload) {
            return detail::write_connection_table(payload, checkpoint.state.ipv6_connections);
        })) {
        return false;
    }

    stream.flush();
    return static_cast<bool>(stream);
}

}  // namespace pfl
