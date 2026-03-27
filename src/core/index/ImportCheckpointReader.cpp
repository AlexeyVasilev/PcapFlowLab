#include "core/index/ImportCheckpointReader.h"

#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include "core/index/Serialization.h"

namespace pfl {

namespace {

[[nodiscard]] std::uint64_t remaining_bytes(std::ifstream& stream) {
    const auto current = stream.tellg();
    if (current < 0) {
        return 0;
    }

    stream.seekg(0, std::ios::end);
    const auto end = stream.tellg();
    stream.seekg(current);
    if (end < current) {
        return 0;
    }

    return static_cast<std::uint64_t>(end - current);
}

template <typename Parser>
bool parse_section_payload(const std::vector<std::uint8_t>& payload, Parser&& parser) {
    const std::string bytes(reinterpret_cast<const char*>(payload.data()), payload.size());
    std::istringstream payload_stream(bytes, std::ios::in | std::ios::binary);
    if (!parser(payload_stream)) {
        return false;
    }

    return payload_stream.peek() == std::char_traits<char>::eof();
}

}  // namespace

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
    ImportCheckpoint checkpoint {};
    bool has_source_info {false};
    bool has_progress {false};
    bool has_summary {false};
    bool has_ipv4_connections {false};
    bool has_ipv6_connections {false};

    if (!detail::read_u64(stream, magic) ||
        !detail::read_u16(stream, version) ||
        !detail::read_u16(stream, reserved) ||
        magic != kImportCheckpointMagic ||
        version != kImportCheckpointVersion) {
        return false;
    }

    while (stream.peek() != std::char_traits<char>::eof()) {
        std::uint32_t raw_section_id {0};
        std::uint64_t payload_size {0};
        if (!detail::read_section_header(stream, raw_section_id, payload_size)) {
            return false;
        }

        if (payload_size > remaining_bytes(stream) ||
            payload_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
            return false;
        }

        std::vector<std::uint8_t> payload {};
        if (!detail::read_section_payload(stream, payload_size, payload)) {
            return false;
        }

        switch (static_cast<detail::ImportCheckpointSectionId>(raw_section_id)) {
        case detail::ImportCheckpointSectionId::source_info:
            if (has_source_info || !parse_section_payload(payload, [&](std::istream& section_stream) {
                return detail::read_capture_source_info(section_stream, checkpoint.source_info);
            })) {
                return false;
            }
            has_source_info = true;
            break;
        case detail::ImportCheckpointSectionId::progress:
            if (has_progress || !parse_section_payload(payload, [&](std::istream& section_stream) {
                std::uint8_t completed {0};
                if (!detail::read_u64(section_stream, checkpoint.packets_processed) ||
                    !detail::read_u64(section_stream, checkpoint.next_input_offset) ||
                    !detail::read_u8(section_stream, completed)) {
                    return false;
                }

                checkpoint.completed = completed != 0;
                return true;
            })) {
                return false;
            }
            has_progress = true;
            break;
        case detail::ImportCheckpointSectionId::summary:
            if (has_summary || !parse_section_payload(payload, [&](std::istream& section_stream) {
                return detail::read_capture_summary(section_stream, checkpoint.state.summary);
            })) {
                return false;
            }
            has_summary = true;
            break;
        case detail::ImportCheckpointSectionId::ipv4_connections:
            if (has_ipv4_connections || !parse_section_payload(payload, [&](std::istream& section_stream) {
                return detail::read_connection_table(section_stream, checkpoint.state.ipv4_connections);
            })) {
                return false;
            }
            has_ipv4_connections = true;
            break;
        case detail::ImportCheckpointSectionId::ipv6_connections:
            if (has_ipv6_connections || !parse_section_payload(payload, [&](std::istream& section_stream) {
                return detail::read_connection_table(section_stream, checkpoint.state.ipv6_connections);
            })) {
                return false;
            }
            has_ipv6_connections = true;
            break;
        default:
            return false;
        }
    }

    if (!has_source_info || !has_progress || !has_summary || !has_ipv4_connections || !has_ipv6_connections) {
        return false;
    }

    out_checkpoint = checkpoint;
    return true;
}

}  // namespace pfl
