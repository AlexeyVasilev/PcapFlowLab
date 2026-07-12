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

class MemoryStreambuf final : public std::streambuf {
public:
    explicit MemoryStreambuf(std::span<const std::uint8_t> bytes) {
        auto* begin = reinterpret_cast<char*>(const_cast<std::uint8_t*>(bytes.data()));
        setg(begin, begin, begin + static_cast<std::streamsize>(bytes.size()));
    }
};

class MemoryIStream final : public std::istream {
public:
    explicit MemoryIStream(std::span<const std::uint8_t> bytes)
        : std::istream(&buffer_)
        , buffer_(bytes) {
    }

private:
    MemoryStreambuf buffer_;
};

template <typename Parser>
bool parse_section_payload(const std::vector<std::uint8_t>& payload, Parser&& parser) {
    MemoryIStream payload_stream(std::span<const std::uint8_t>(payload.data(), payload.size()));
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

    std::uint64_t failure_offset {0};

    try {
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
        bool has_protocol_paths {false};
        bool has_ipv4_connections {false};
        bool has_ipv6_connections {false};
        bool has_unrecognized_packets {false};

        failure_offset = current_offset(stream);
        if (!detail::read_u64(stream, magic) ||
            !detail::read_u16(stream, version) ||
            !detail::read_u16(stream, reserved)) {
            set_error_context(failure_offset, "index file is incomplete or was not finalized");
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
            set_error_context(0, "unsupported index version; rebuild the index from the source capture");
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

            const auto section_header_offset = current_offset(stream);
            failure_offset = section_header_offset;

            std::uint32_t raw_section_id {0};
            std::uint64_t payload_size {0};
            if (!detail::read_section_header(stream, raw_section_id, payload_size)) {
                set_error_context(section_header_offset, "index file is incomplete or was not finalized");
                if (ctx != nullptr) {
                    ctx->set_failure(last_error_);
                }
                return false;
            }

            const auto payload_offset = current_offset(stream);
            failure_offset = payload_offset;

            if (payload_size > remaining_bytes(stream)) {
                set_error_context(section_header_offset, "index file is incomplete or was not finalized");
                if (ctx != nullptr) {
                    ctx->set_failure(last_error_);
                }
                return false;
            }

            if (payload_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
                set_error_context(section_header_offset, "invalid section length");
                if (ctx != nullptr) {
                    ctx->set_failure(last_error_);
                }
                return false;
            }

            std::vector<std::uint8_t> payload {};
            if (!detail::read_section_payload(stream, payload_size, payload)) {
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

            switch (static_cast<detail::CaptureIndexSectionId>(raw_section_id)) {
            case detail::CaptureIndexSectionId::source_info:
                if (has_source_info || !parse_section_payload(payload, [&](std::istream& section_stream) {
                    return detail::read_capture_source_info(section_stream, source_info);
                })) {
                    set_error_context(section_header_offset, "invalid source-info section");
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
                    set_error_context(section_header_offset, "invalid summary section");
                    if (ctx != nullptr) {
                        ctx->set_failure(last_error_);
                    }
                    return false;
                }
                has_summary = true;
                break;
            case detail::CaptureIndexSectionId::protocol_paths:
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
                if (!parse_section_payload(payload, [&](std::istream& section_stream) {
                    return detail::read_connection_table_chunk(section_stream, state.ipv4_connections);
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
                if (!parse_section_payload(payload, [&](std::istream& section_stream) {
                    return detail::read_connection_table_chunk(section_stream, state.ipv6_connections);
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
                if (has_unrecognized_packets || !parse_section_payload(payload, [&](std::istream& section_stream) {
                    return detail::read_unrecognized_packet_records(section_stream, state.unrecognized_packets);
                })) {
                    set_error_context(section_header_offset, "invalid unrecognized-packets section");
                    if (ctx != nullptr) {
                        ctx->set_failure(last_error_);
                    }
                    return false;
                }
                has_unrecognized_packets = true;
                break;
            default:
                set_error_context(section_header_offset, "unknown index section");
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

        if (!has_source_info || !has_summary || !has_protocol_paths || !has_ipv4_connections || !has_ipv6_connections) {
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

