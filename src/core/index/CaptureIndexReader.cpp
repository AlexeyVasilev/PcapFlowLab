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
constexpr char kPreviousStableV15RebuildMessage[] =
    "This index uses revision 15 and must be rebuilt with the current version.";
constexpr char kOutdatedStableIndexRebuildMessage[] =
    "stable index revision is outdated; rebuild the index from the source capture";
constexpr char kFutureStableIndexRevisionMessage[] =
    "stable index revision is newer than this application supports";

[[nodiscard]] const char* outdated_stable_revision_message(const std::uint32_t revision) noexcept {
    return revision == kCaptureIndexPreviousStableV15Revision
        ? kPreviousStableV15RebuildMessage
        : kOutdatedStableIndexRebuildMessage;
}

[[nodiscard]] const char* v16_complete_read_error_text(const detail::CaptureIndexV16CompleteReadResult& result) noexcept {
    if (!result.error_detail.empty()) {
        return result.error_detail.c_str();
    }

    switch (result.status) {
    case detail::CaptureIndexV16CompleteReadStatus::ok:
        return "";
    case detail::CaptureIndexV16CompleteReadStatus::cancelled:
        return "v16 index load was cancelled";
    case detail::CaptureIndexV16CompleteReadStatus::invalid_metadata_tier:
        return "invalid v16 index metadata tier";
    case detail::CaptureIndexV16CompleteReadStatus::trailing_data:
        return "invalid v16 index trailing data";
    }

    return "invalid v16 index";
}

[[nodiscard]] const char* v16_fast_statistics_read_error_text(
    const detail::CaptureIndexV16FastStatisticsTierReadResult& result
) noexcept {
    if (!result.error_detail.empty()) {
        return result.error_detail.c_str();
    }

    switch (result.status) {
    case detail::CaptureIndexV16FastStatisticsTierReadStatus::ok:
        return "";
    case detail::CaptureIndexV16FastStatisticsTierReadStatus::invalid_header:
        return "invalid stable index header";
    case detail::CaptureIndexV16FastStatisticsTierReadStatus::unsupported_revision:
        return "unsupported stable index revision";
    case detail::CaptureIndexV16FastStatisticsTierReadStatus::missing_capture_statistics_snapshot_section:
        return "missing v16 capture statistics snapshot section";
    case detail::CaptureIndexV16FastStatisticsTierReadStatus::duplicate_capture_statistics_snapshot_section:
        return "duplicate v16 capture statistics snapshot section";
    case detail::CaptureIndexV16FastStatisticsTierReadStatus::missing_protocol_path_registry_early_section:
        return "missing v16 protocol path registry section";
    case detail::CaptureIndexV16FastStatisticsTierReadStatus::duplicate_protocol_path_registry_early_section:
        return "duplicate v16 protocol path registry section";
    case detail::CaptureIndexV16FastStatisticsTierReadStatus::missing_protocol_path_terminal_aggregates_section:
        return "missing v16 protocol path terminal aggregates section";
    case detail::CaptureIndexV16FastStatisticsTierReadStatus::wrong_fast_section_order:
        return "invalid v16 fast statistics section order";
    case detail::CaptureIndexV16FastStatisticsTierReadStatus::invalid_fast_section_framing:
        return "invalid v16 fast statistics section framing";
    case detail::CaptureIndexV16FastStatisticsTierReadStatus::unsupported_fast_section_schema:
        return "unsupported v16 fast statistics section schema";
    case detail::CaptureIndexV16FastStatisticsTierReadStatus::truncated_fast_section_payload:
        return "truncated v16 fast statistics section payload";
    case detail::CaptureIndexV16FastStatisticsTierReadStatus::malformed_capture_statistics_snapshot_payload:
        return "malformed v16 capture statistics snapshot payload";
    case detail::CaptureIndexV16FastStatisticsTierReadStatus::capture_statistics_snapshot_semantic_inconsistency:
        return "invalid v16 capture statistics snapshot";
    case detail::CaptureIndexV16FastStatisticsTierReadStatus::malformed_protocol_path_registry_payload:
        return "malformed v16 protocol path registry payload";
    case detail::CaptureIndexV16FastStatisticsTierReadStatus::malformed_protocol_path_terminal_aggregates_payload:
        return "malformed v16 protocol path terminal aggregates payload";
    case detail::CaptureIndexV16FastStatisticsTierReadStatus::protocol_path_terminal_aggregates_semantic_inconsistency:
        return "invalid v16 protocol path terminal aggregates";
    case detail::CaptureIndexV16FastStatisticsTierReadStatus::fast_tier_cross_section_inconsistency:
        return "invalid v16 fast statistics tier";
    }

    return "invalid v16 fast statistics tier";
}

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

bool CaptureIndexReader::read_v16_complete(
    const std::filesystem::path& index_path,
    detail::CaptureIndexV16CompleteReadResult& out_result,
    OpenContext* ctx
) const {
    out_result = {};
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

    try {
        report_index_progress(ctx, stream);
        if (should_cancel(ctx)) {
            report_index_progress(ctx, stream);
            return false;
        }

        std::uint64_t magic {0};
        if (!detail::read_u64(stream, magic)) {
            set_error_context(0, "index file is incomplete or was not finalized");
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        if (magic == kLegacyCaptureIndexMagic) {
            std::uint16_t legacy_version {0};
            std::uint16_t legacy_reserved {0};
            if (!detail::read_u16(stream, legacy_version) ||
                !detail::read_u16(stream, legacy_reserved)) {
                set_error_context(current_offset(stream), "index file is incomplete or was not finalized");
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
            set_error_context(0, outdated_stable_revision_message(stable_header.index_revision));
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        if (stable_header.index_revision > kCaptureIndexStableIndexRevision) {
            set_error_context(0, kFutureStableIndexRevisionMessage);
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        stream.seekg(0, std::ios::beg);
        const detail::CaptureIndexV16ReadControl read_control {
            .cancel_requested = [ctx]() {
                return should_cancel(ctx);
            },
            .progress_callback = [ctx](const std::uint64_t processed, const std::uint64_t total) {
                if (ctx != nullptr) {
                    ctx->progress.bytes_processed = processed;
                    ctx->progress.total_bytes = total;
                    if (ctx->on_progress) {
                        ctx->on_progress(ctx->progress);
                    }
                }
                return !should_cancel(ctx);
            },
            .total_bytes = ctx != nullptr ? ctx->progress.total_bytes : 0U,
        };
        out_result = detail::read_capture_index_v16(stream, &read_control);
        if (!out_result) {
            if (out_result.status == detail::CaptureIndexV16CompleteReadStatus::cancelled) {
                report_index_progress(ctx, stream);
                return false;
            }
            set_error_context(0, v16_complete_read_error_text(out_result));
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        report_index_progress(ctx, stream);
        return true;
    } catch (const std::bad_alloc&) {
        last_error_ = {};
        last_error_.reason = "index load exhausted memory while reading v16 metadata";
        if (ctx != nullptr) {
            ctx->set_failure(last_error_);
        }
        return false;
    } catch (const std::exception& error) {
        last_error_ = {};
        last_error_.reason = std::string("unexpected exception while reading v16 index: ") + error.what();
        if (ctx != nullptr) {
            ctx->set_failure(last_error_);
        }
        return false;
    }
}

bool CaptureIndexReader::read_v16_fast_statistics(
    const std::filesystem::path& index_path,
    detail::CaptureIndexV16FastStatisticsTier& out_tier,
    detail::CaptureIndexV16FastStatisticsTierReadResult& out_result,
    OpenContext* ctx
) const {
    out_tier = {};
    out_result = {};
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

    try {
        report_index_progress(ctx, stream);
        if (should_cancel(ctx)) {
            report_index_progress(ctx, stream);
            return false;
        }

        std::uint64_t magic {0};
        if (!detail::read_u64(stream, magic)) {
            set_error_context(0, "index file is incomplete or was not finalized");
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        if (magic == kLegacyCaptureIndexMagic) {
            std::uint16_t legacy_version {0};
            std::uint16_t legacy_reserved {0};
            if (!detail::read_u16(stream, legacy_version) ||
                !detail::read_u16(stream, legacy_reserved)) {
                set_error_context(current_offset(stream), "index file is incomplete or was not finalized");
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
            set_error_context(0, outdated_stable_revision_message(stable_header.index_revision));
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        if (stable_header.index_revision > kCaptureIndexStableIndexRevision) {
            set_error_context(0, kFutureStableIndexRevisionMessage);
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        stream.seekg(0, std::ios::beg);
        out_result = detail::read_v16_fast_statistics_tier(stream, out_tier);
        if (!out_result) {
            set_error_context(0, v16_fast_statistics_read_error_text(out_result));
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        report_index_progress(ctx, stream);
        return true;
    } catch (const std::bad_alloc&) {
        last_error_ = {};
        last_error_.reason = "index load exhausted memory while reading v16 fast statistics";
        if (ctx != nullptr) {
            ctx->set_failure(last_error_);
        }
        return false;
    } catch (const std::exception& error) {
        last_error_ = {};
        last_error_.reason = std::string("unexpected exception while reading v16 fast statistics: ") + error.what();
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
        state.packet_statistics = {};
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
            set_error_context(0, outdated_stable_revision_message(stable_header.index_revision));
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        if (stable_header.index_revision > kCaptureIndexStableIndexRevision) {
            set_error_context(0, kFutureStableIndexRevisionMessage);
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        if (stable_header.index_revision == kCaptureIndexStableIndexRevision) {
            set_error_context(0, "legacy eager index reader does not support v16 metadata-backed indexes");
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
                        &state.packet_statistics
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
                        &state.packet_statistics
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
                        &state.packet_statistics
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

