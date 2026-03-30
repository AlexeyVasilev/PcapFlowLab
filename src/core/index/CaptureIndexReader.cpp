#include "core/index/CaptureIndexReader.h"

#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <system_error>
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

    report_index_progress(ctx, stream);
    if (should_cancel(ctx)) {
        report_index_progress(ctx, stream);
        return false;
    }

    std::uint64_t magic {0};
    std::uint16_t version {0};
    std::uint16_t reserved {0};
    CaptureSourceInfo source_info {};
    CaptureState state {};
    bool has_source_info {false};
    bool has_summary {false};
    bool has_ipv4_connections {false};
    bool has_ipv6_connections {false};

    if (!detail::read_u64(stream, magic) ||
        !detail::read_u16(stream, version) ||
        !detail::read_u16(stream, reserved)) {
        set_error_context(current_offset(stream), "unexpected EOF while reading index header");
        if (ctx != nullptr) {
            ctx->set_failure(last_error_);
        }
        return false;
    }

    if (magic != kCaptureIndexMagic) {
        set_error_context(0, "invalid index magic");
        if (ctx != nullptr) {
            ctx->set_failure(last_error_);
        }
        return false;
    }

    if (version != kCaptureIndexVersion) {
        set_error_context(0, "unsupported index version");
        if (ctx != nullptr) {
            ctx->set_failure(last_error_);
        }
        return false;
    }

    report_index_progress(ctx, stream);

    while (stream.peek() != std::char_traits<char>::eof()) {
        if (should_cancel(ctx)) {
            report_index_progress(ctx, stream);
            return false;
        }

        std::uint32_t raw_section_id {0};
        std::uint64_t payload_size {0};
        if (!detail::read_section_header(stream, raw_section_id, payload_size)) {
            set_error_context(current_offset(stream), "failed to read section header");
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        if (payload_size > remaining_bytes(stream) ||
            payload_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
            set_error_context(current_offset(stream), "invalid section length");
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }

        std::vector<std::uint8_t> payload {};
        if (!detail::read_section_payload(stream, payload_size, payload)) {
            set_error_context(current_offset(stream), "unexpected EOF while reading section payload");
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

        switch (static_cast<detail::CaptureIndexSectionId>(raw_section_id)) {
        case detail::CaptureIndexSectionId::source_info:
            if (has_source_info || !parse_section_payload(payload, [&](std::istream& section_stream) {
                return detail::read_capture_source_info(section_stream, source_info);
            })) {
                set_error_context(current_offset(stream), "invalid source-info section");
                if (ctx != nullptr) {
                    ctx->set_failure(last_error_);
                }
                return false;
            }
            has_source_info = true;
            break;
        case detail::CaptureIndexSectionId::summary:
            if (has_summary || !parse_section_payload(payload, [&](std::istream& section_stream) {
                return detail::read_capture_summary(section_stream, state.summary);
            })) {
                set_error_context(current_offset(stream), "invalid summary section");
                if (ctx != nullptr) {
                    ctx->set_failure(last_error_);
                }
                return false;
            }
            has_summary = true;
            break;
        case detail::CaptureIndexSectionId::ipv4_connections:
            if (has_ipv4_connections || !parse_section_payload(payload, [&](std::istream& section_stream) {
                return detail::read_connection_table(section_stream, state.ipv4_connections);
            })) {
                set_error_context(current_offset(stream), "invalid IPv4 connection section");
                if (ctx != nullptr) {
                    ctx->set_failure(last_error_);
                }
                return false;
            }
            has_ipv4_connections = true;
            break;
        case detail::CaptureIndexSectionId::ipv6_connections:
            if (has_ipv6_connections || !parse_section_payload(payload, [&](std::istream& section_stream) {
                return detail::read_connection_table(section_stream, state.ipv6_connections);
            })) {
                set_error_context(current_offset(stream), "invalid IPv6 connection section");
                if (ctx != nullptr) {
                    ctx->set_failure(last_error_);
                }
                return false;
            }
            has_ipv6_connections = true;
            break;
        default:
            set_error_context(current_offset(stream), "unknown index section");
            if (ctx != nullptr) {
                ctx->set_failure(last_error_);
            }
            return false;
        }
    }

    if (should_cancel(ctx)) {
        report_index_progress(ctx, stream);
        return false;
    }

    if (!has_source_info || !has_summary || !has_ipv4_connections || !has_ipv6_connections) {
        set_error_context(current_offset(stream), "missing required index sections");
        if (ctx != nullptr) {
            ctx->set_failure(last_error_);
        }
        return false;
    }

    out_state = state;
    out_source_capture_path = source_info.capture_path;
    if (out_source_info != nullptr) {
        *out_source_info = source_info;
    }

    report_index_progress(ctx, stream);
    return true;
}

}  // namespace pfl

