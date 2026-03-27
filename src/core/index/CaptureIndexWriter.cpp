#include "core/index/CaptureIndexWriter.h"

#include <fstream>
#include <sstream>
#include <string>

#include "core/index/CaptureIndex.h"
#include "core/index/Serialization.h"

namespace pfl {

namespace {

template <typename Writer>
bool write_marshaled_section(std::ofstream& stream, const detail::CaptureIndexSectionId section_id, Writer&& writer) {
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
        !write_marshaled_section(stream, detail::CaptureIndexSectionId::source_info, [&](std::ostream& payload) {
            return detail::write_capture_source_info(payload, source_info);
        }) ||
        !write_marshaled_section(stream, detail::CaptureIndexSectionId::summary, [&](std::ostream& payload) {
            return detail::write_capture_summary(payload, state.summary);
        }) ||
        !write_marshaled_section(stream, detail::CaptureIndexSectionId::ipv4_connections, [&](std::ostream& payload) {
            return detail::write_connection_table(payload, state.ipv4_connections);
        }) ||
        !write_marshaled_section(stream, detail::CaptureIndexSectionId::ipv6_connections, [&](std::ostream& payload) {
            return detail::write_connection_table(payload, state.ipv6_connections);
        })) {
        return false;
    }

    stream.flush();
    return static_cast<bool>(stream);
}

}  // namespace pfl
