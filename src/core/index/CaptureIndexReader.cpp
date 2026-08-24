#include "core/index/CaptureIndexReader.h"

#include <fstream>
#include <exception>
#include <limits>
#include <new>
#include <span>
#include <streambuf>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "../../../core/open_context.h"
#include "core/index/Serialization.h"

namespace pfl {

namespace {

[[nodiscard]] std::uint64_t current_offset(std::ifstream& stream) {
    const auto current = stream.tellg();
    if (current < 0) {
        return 0;
    }

    return static_cast<std::uint64_t>(current);
}

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

void report_index_progress(OpenContext* ctx, std::ifstream& stream) {
    if (ctx == nullptr) {
        return;
    }

    ctx->progress.bytes_processed = current_offset(stream);
    if (ctx->on_progress) {
        ctx->on_progress(ctx->progress);
    }
}

[[nodiscard]] bool should_cancel(const OpenContext* ctx) noexcept {
    return ctx != nullptr && ctx->is_cancel_requested();
}

class MemoryStreambuf : public std::streambuf {
public:
    explicit MemoryStreambuf(std::span<const std::uint8_t> bytes) {
        auto* begin = reinterpret_cast<char*>(const_cast<std::uint8_t*>(bytes.data()));
        setg(begin, begin, begin + static_cast<std::streamsize>(bytes.size()));
    }
};

class MemoryIStream final : private MemoryStreambuf, public std::istream {
public:
    explicit MemoryIStream(std::span<const std::uint8_t> bytes)
        : MemoryStreambuf(bytes)
        , std::istream(static_cast<MemoryStreambuf*>(this)) {
    }
};

template <typename Parser>
bool parse_section_payload(const std::vector<std::uint8_t>& payload, Parser&& parser) {
    MemoryIStream payload_stream(std::span<const std::uint8_t>(payload.data(), payload.size()));
    if (!parser(payload_stream)) {
        return false;
    }

    return payload_stream.peek() == std::char_traits<char>::eof();
}

[[nodiscard]] bool skip_exact_bytes(std::ifstream& stream, const std::uint64_t byte_count) {
    if (byte_count == 0U) {
        return true;
    }

    if (byte_count > static_cast<std::uint64_t>((std::numeric_limits<std::streamoff>::max)())) {
        return false;
    }

    stream.seekg(static_cast<std::streamoff>(byte_count), std::ios::cur);
    return stream.good();
}

[[nodiscard]] CaptureSourceInfo stable_header_source_info(const detail::CaptureIndexStableHeader& header) {
    return CaptureSourceInfo {
        .capture_path = detail::filesystem_path_from_generic_utf8(header.source_capture_path_utf8),
        .format = header.source_format,
        .file_size = header.source_file_size,
        .last_write_time = header.source_last_write_time,
        .content_fingerprint = header.source_content_fingerprint,
    };
}

constexpr char kLegacyIndexRebuildMessage[] =
    "legacy index version 14 is no longer loadable; rebuild the index from the source capture";
constexpr char kCompactPacketRefRebuildMessage[] =
    "stable index uses legacy packet-ref storage for packet metadata; rebuild the index from the source capture";

}  // namespace

const OpenFailureInfo& CaptureIndexReader::last_error() const noexcept {
    return last_error_;
}

void CaptureIndexReader::clear_error() const {
    last_error_ = {};
}

void CaptureIndexReader::set_error_context(std::uint64_t file_offset, const char* reason) const {
    last_error_ = {};
    last_error_.has_file_offset = true;
    last_error_.file_offset = file_offset;
    last_error_.reason = reason;
}

void CaptureIndexReader::set_error_context(const char* reason) const {
    last_error_ = {};
    last_error_.reason = reason;
}

bool CaptureIndexReader::inspect(const std::filesystem::path& index_path,
                                 CaptureIndexInspection& out_inspection,
                                 OpenContext* ctx) const {
    out_inspection = {};
    clear_error();

    if (ctx != nullptr) {
        ctx->progress = {};
        ctx->clear_failure();
        std::error_code error {};
        const auto file_size = std::filesystem::file_size(index_path, error);
        if (!error) {
            ctx->progress.total_bytes = static_cast<std::uint64_t>(file_size);
        }
    }

    if (should_cancel(ctx)) {
        if (ctx != nullptr && ctx->on_progress) {
            ctx->on_progress(ctx->progress);
        }
        return false;
    }

    std::ifstream stream(index_path, std::ios::binary);
    if (!stream.is_open()) {
        set_error_context("file access failed");
        if (ctx != nullptr) {
            ctx->set_failure(last_error_);
        }
        return false;
    }

    std::uint64_t failure_offset {0};

    try {
        failure_offset = current_offset(stream);
        if (!detail::read_u64(stream, out_inspection.magic)) {
            set_error_context(failure_offset, "index file is incomplete or was not finalized");
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        if (out_inspection.magic == kLegacyCaptureIndexMagic) {
            out_inspection.format_family = CaptureIndexFormatFamily::legacy;
            failure_offset = current_offset(stream);
            if (!detail::read_u16(stream, out_inspection.legacy_version) ||
                !detail::read_u16(stream, out_inspection.legacy_reserved)) {
                set_error_context(failure_offset, "index file is incomplete or was not finalized");
                if (ctx != nullptr) {
                    ctx->set_failure(last_error_);
                }
                return false;
            }

            report_index_progress(ctx, stream);
            return true;
        }

        if (out_inspection.magic != kStableCaptureIndexMagic) {
            set_error_context(0, "invalid index magic");
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        stream.seekg(0, std::ios::beg);
        detail::CaptureIndexStableHeader stable_header {};
        if (!detail::read_capture_index_stable_header(stream, stable_header)) {
            set_error_context(0, "invalid stable index header");
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        out_inspection.format_family = CaptureIndexFormatFamily::stable;
        out_inspection.magic = stable_header.magic;
        out_inspection.stable_container_format_version = stable_header.container_format_version;
        out_inspection.stable_header_flags = stable_header.header_flags;
        out_inspection.stable_header_size = stable_header.header_size;
        out_inspection.stable_index_revision = stable_header.index_revision;
        out_inspection.writer_application_version = stable_header.writer_application_version;
        out_inspection.source_info = stable_header_source_info(stable_header);

        report_index_progress(ctx, stream);
        while (stream.peek() != std::char_traits<char>::eof()) {
            if (should_cancel(ctx)) {
                report_index_progress(ctx, stream);
                return false;
            }

            const auto section_offset = current_offset(stream);
            detail::CaptureIndexStableSectionHeader section_header {};
            if (!detail::read_capture_index_stable_section_header(stream, section_header)) {
                set_error_context(section_offset, "index file is incomplete or was not finalized");
                if (ctx != nullptr) {
                    ctx->set_failure(last_error_);
                }
                return false;
            }

            if (section_header.payload_size > remaining_bytes(stream) ||
                !skip_exact_bytes(stream, section_header.payload_size)) {
                set_error_context(section_offset, "index file is incomplete or was not finalized");
                if (ctx != nullptr) {
                    ctx->set_failure(last_error_);
                }
                return false;
            }

            out_inspection.sections.push_back(CaptureIndexInspectionSection {
                .section_id = section_header.section_id,
                .section_schema_version = section_header.section_schema_version,
                .section_flags = section_header.section_flags,
                .payload_size = section_header.payload_size,
                .file_offset = section_offset,
            });
            report_index_progress(ctx, stream);
        }

        return true;
    } catch (const std::bad_alloc&) {
        last_error_ = {};
        last_error_.has_file_offset = true;
        last_error_.file_offset = failure_offset;
        last_error_.reason = "index inspection exhausted memory";
        if (ctx != nullptr) {
            ctx->set_failure(last_error_);
        }
        return false;
    } catch (const std::exception& error) {
        last_error_ = {};
        last_error_.has_file_offset = true;
        last_error_.file_offset = failure_offset;
        last_error_.reason = std::string("unexpected exception while inspecting index: ") + error.what();
        if (ctx != nullptr) {
            ctx->set_failure(last_error_);
        }
        return false;
    }
}

bool CaptureIndexReader::read(const std::filesystem::path& index_path,
                              CaptureState& out_state,
                              std::filesystem::path& out_source_capture_path,
                              CaptureSourceInfo* out_source_info,
                              OpenContext* ctx) const {
    out_state = {};
    out_source_capture_path.clear();
    if (out_source_info != nullptr) {
        *out_source_info = {};
    }
    clear_error();

    if (ctx != nullptr) {
        ctx->progress = {};
        ctx->clear_failure();
        std::error_code error {};
        const auto file_size = std::filesystem::file_size(index_path, error);
        if (!error) {
            ctx->progress.total_bytes = static_cast<std::uint64_t>(file_size);
        }
    }

    if (should_cancel(ctx)) {
        if (ctx != nullptr && ctx->on_progress) {
            ctx->on_progress(ctx->progress);
        }
        return false;
    }

    std::ifstream stream(index_path, std::ios::binary);
    if (!stream.is_open()) {
        set_error_context("file access failed");
        if (ctx != nullptr) {
            ctx->set_failure(last_error_);
        }
        return false;
    }

    std::uint64_t failure_offset {0};

    try {
        report_index_progress(ctx, stream);
        if (should_cancel(ctx)) {
            report_index_progress(ctx, stream);
            return false;
        }

        CaptureSourceInfo source_info {};
        CaptureState state {};
        state.packet_size_statistics = {};
        bool has_summary {false};
        bool has_protocol_paths {false};
        bool has_ipv4_connections {false};
        bool has_ipv6_connections {false};
        bool has_unrecognized_packets {false};
        bool has_packet_locator {false};

        std::uint64_t magic {0};
        failure_offset = current_offset(stream);
        if (!detail::read_u64(stream, magic)) {
            set_error_context(failure_offset, "index file is incomplete or was not finalized");
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        if (magic == kLegacyCaptureIndexMagic) {
            std::uint16_t legacy_version {0};
            std::uint16_t legacy_reserved {0};
            failure_offset = current_offset(stream);
            if (!detail::read_u16(stream, legacy_version) ||
                !detail::read_u16(stream, legacy_reserved)) {
                set_error_context(failure_offset, "index file is incomplete or was not finalized");
            } else {
                set_error_context(0, kLegacyIndexRebuildMessage);
            }
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        if (magic != kStableCaptureIndexMagic) {
            set_error_context(0, "invalid index magic");
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        stream.seekg(0, std::ios::beg);
        detail::CaptureIndexStableHeader stable_header {};
        if (!detail::read_capture_index_stable_header(stream, stable_header)) {
            set_error_context(0, "invalid stable index header");
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        if (stable_header.container_format_version != kCaptureIndexStableContainerFormatVersion) {
            set_error_context(0, "unsupported stable index container version");
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        if (stable_header.index_revision < kCaptureIndexStableIndexRevision) {
            set_error_context(0, "unsupported stable index revision");
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        source_info = stable_header_source_info(stable_header);
        report_index_progress(ctx, stream);

        while (stream.peek() != std::char_traits<char>::eof()) {
            if (should_cancel(ctx)) {
                report_index_progress(ctx, stream);
                return false;
            }

            const auto section_header_offset = current_offset(stream);
            failure_offset = section_header_offset;

            detail::CaptureIndexStableSectionHeader section_header {};
            if (!detail::read_capture_index_stable_section_header(stream, section_header)) {
                set_error_context(section_header_offset, "index file is incomplete or was not finalized");
                if (ctx != nullptr) {
                    ctx->set_failure(last_error_);
                }
                return false;
            }

            const auto payload_offset = current_offset(stream);
            failure_offset = payload_offset;

            if (section_header.payload_size > remaining_bytes(stream)) {
                set_error_context(section_header_offset, "index file is incomplete or was not finalized");
                if (ctx != nullptr) {
                    ctx->set_failure(last_error_);
                }
                return false;
            }

            const auto required_section =
                (section_header.section_flags & detail::kCaptureIndexStableSectionFlagRequired) != 0U;
            const auto section_id = static_cast<detail::CaptureIndexSectionId>(section_header.section_id);
            auto invalid_core_section_header = [&](const char* reason) {
                set_error_context(section_header_offset, reason);
                if (ctx != nullptr) {
                    ctx->set_failure(last_error_);
                }
            };

            const bool known_section =
                section_id == detail::CaptureIndexSectionId::source_info ||
                section_id == detail::CaptureIndexSectionId::summary ||
                section_id == detail::CaptureIndexSectionId::protocol_paths ||
                section_id == detail::CaptureIndexSectionId::ipv4_connections ||
                section_id == detail::CaptureIndexSectionId::ipv6_connections ||
                section_id == detail::CaptureIndexSectionId::unrecognized_packets ||
                section_id == detail::CaptureIndexSectionId::packet_locator;

            if (!known_section) {
                if (required_section) {
                    set_error_context(section_header_offset, "unsupported required index section");
                    if (ctx != nullptr) {
                        ctx->set_failure(last_error_);
                    }
                    return false;
                }

                if (!skip_exact_bytes(stream, section_header.payload_size)) {
                    set_error_context(payload_offset, "index file is incomplete or was not finalized");
                    if (ctx != nullptr) {
                        ctx->set_failure(last_error_);
                    }
                    return false;
                }

                report_index_progress(ctx, stream);
                if (should_cancel(ctx)) {
                    report_index_progress(ctx, stream);
                    return false;
                }
                continue;
            }

            if (section_header.payload_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
                set_error_context(section_header_offset, "invalid section length");
                if (ctx != nullptr) {
                    ctx->set_failure(last_error_);
                }
                return false;
            }

            std::vector<std::uint8_t> payload {};
            if (!detail::read_section_payload(stream, section_header.payload_size, payload)) {
                set_error_context(payload_offset, "index file is incomplete or was not finalized");
                if (ctx != nullptr) {
                    ctx->set_failure(last_error_);
                }
                return false;
            }

            report_index_progress(ctx, stream);
            if (should_cancel(ctx)) {
                report_index_progress(ctx, stream);
                return false;
            }

            switch (section_id) {
            case detail::CaptureIndexSectionId::source_info:
                invalid_core_section_header("reserved source-info section is not supported in stable indexes");
                return false;
            case detail::CaptureIndexSectionId::summary:
                if (!required_section ||
                    section_header.section_schema_version != detail::kCaptureIndexStableSummarySectionSchemaVersion ||
                    has_summary) {
                    invalid_core_section_header("invalid summary section");
                    return false;
                }
                if (has_summary || !parse_section_payload(payload, [&](std::istream& section_stream) {
                    return detail::read_capture_summary(section_stream, state.summary);
                })) {
                    set_error_context(section_header_offset, "invalid summary section");
                    if (ctx != nullptr) {
                        ctx->set_failure(last_error_);
                    }
                    return false;
                }
                has_summary = true;
                break;
            case detail::CaptureIndexSectionId::protocol_paths:
                if (!required_section ||
                    section_header.section_schema_version != detail::kCaptureIndexStableProtocolPathsSectionSchemaVersion ||
                    has_protocol_paths) {
                    invalid_core_section_header("invalid protocol-path section");
                    return false;
                }
                if (has_protocol_paths || !parse_section_payload(payload, [&](std::istream& section_stream) {
                    return detail::read_protocol_path_registry(section_stream, state.protocol_path_registry);
                })) {
                    set_error_context(section_header_offset, "invalid protocol-path section");
                    if (ctx != nullptr) {
                        ctx->set_failure(last_error_);
                    }
                    return false;
                }
                has_protocol_paths = true;
                break;
            case detail::CaptureIndexSectionId::ipv4_connections:
                if (!required_section) {
                    invalid_core_section_header("invalid IPv4 connection section");
                    return false;
                }
                if (section_header.section_schema_version == 1U) {
                    invalid_core_section_header(kCompactPacketRefRebuildMessage);
                    return false;
                }
                if (section_header.section_schema_version != detail::kCaptureIndexStableIpv4ConnectionsSectionSchemaVersion) {
                    invalid_core_section_header("invalid IPv4 connection section");
                    return false;
                }
                if (!parse_section_payload(payload, [&](std::istream& section_stream) {
                    return detail::read_connection_table_chunk(
                        section_stream,
                        state.ipv4_connections,
                        &state.packet_size_statistics
                    );
                })) {
                    set_error_context(section_header_offset, "invalid IPv4 connection section");
                    if (ctx != nullptr) {
                        ctx->set_failure(last_error_);
                    }
                    return false;
                }
                has_ipv4_connections = true;
                break;
            case detail::CaptureIndexSectionId::ipv6_connections:
                if (!required_section) {
                    invalid_core_section_header("invalid IPv6 connection section");
                    return false;
                }
                if (section_header.section_schema_version == 1U) {
                    invalid_core_section_header(kCompactPacketRefRebuildMessage);
                    return false;
                }
                if (section_header.section_schema_version != detail::kCaptureIndexStableIpv6ConnectionsSectionSchemaVersion) {
                    invalid_core_section_header("invalid IPv6 connection section");
                    return false;
                }
                if (!parse_section_payload(payload, [&](std::istream& section_stream) {
                    return detail::read_connection_table_chunk(
                        section_stream,
                        state.ipv6_connections,
                        &state.packet_size_statistics
                    );
                })) {
                    set_error_context(section_header_offset, "invalid IPv6 connection section");
                    if (ctx != nullptr) {
                        ctx->set_failure(last_error_);
                    }
                    return false;
                }
                has_ipv6_connections = true;
                break;
            case detail::CaptureIndexSectionId::unrecognized_packets:
                if (!required_section || has_unrecognized_packets) {
                    invalid_core_section_header("invalid unrecognized-packets section");
                    return false;
                }
                if (section_header.section_schema_version == 1U) {
                    invalid_core_section_header(kCompactPacketRefRebuildMessage);
                    return false;
                }
                if (section_header.section_schema_version != detail::kCaptureIndexStableUnrecognizedPacketsSectionSchemaVersion) {
                    invalid_core_section_header("invalid unrecognized-packets section");
                    return false;
                }
                if (has_unrecognized_packets || !parse_section_payload(payload, [&](std::istream& section_stream) {
                    return detail::read_unrecognized_packet_records(
                        section_stream,
                        state.unrecognized_packets,
                        &state.packet_size_statistics
                    );
                })) {
                    set_error_context(section_header_offset, "invalid unrecognized-packets section");
                    if (ctx != nullptr) {
                        ctx->set_failure(last_error_);
                    }
                    return false;
                }
                has_unrecognized_packets = true;
                break;
            case detail::CaptureIndexSectionId::packet_locator:
                if (!required_section ||
                    section_header.section_schema_version != detail::kCaptureIndexStablePacketLocatorSectionSchemaVersion ||
                    has_packet_locator) {
                    invalid_core_section_header("invalid packet-locator section");
                    return false;
                }
                if (has_packet_locator || !parse_section_payload(payload, [&](std::istream& section_stream) {
                    return detail::read_capture_packet_locator(section_stream, state.packet_locator);
                })) {
                    set_error_context(section_header_offset, "invalid packet-locator section");
                    if (ctx != nullptr) {
                        ctx->set_failure(last_error_);
                    }
                    return false;
                }
                has_packet_locator = true;
                break;
            default:
                break;
            }
        }

        if (should_cancel(ctx)) {
            report_index_progress(ctx, stream);
            return false;
        }

        if (!has_summary || !has_protocol_paths || !has_ipv4_connections ||
            !has_ipv6_connections || !has_unrecognized_packets || !has_packet_locator) {
            set_error_context(current_offset(stream), "index file is incomplete or was not finalized");
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        out_state = std::move(state);
        out_source_capture_path = source_info.capture_path;
        if (out_source_info != nullptr) {
            *out_source_info = std::move(source_info);
        }

        report_index_progress(ctx, stream);
        return true;
    } catch (const std::bad_alloc&) {
        last_error_ = {};
        last_error_.has_file_offset = true;
        last_error_.file_offset = failure_offset;
        last_error_.reason = "index load exhausted memory while reading a large section";
        if (ctx != nullptr) {
            ctx->set_failure(last_error_);
        }
        return false;
    } catch (const std::exception& error) {
        last_error_ = {};
        last_error_.has_file_offset = true;
        last_error_.file_offset = failure_offset;
        last_error_.reason = std::string("unexpected exception while reading index: ") + error.what();
        if (ctx != nullptr) {
            ctx->set_failure(last_error_);
        }
        return false;
    }
}

}  // namespace pfl

