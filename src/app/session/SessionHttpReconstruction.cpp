#include "app/session/SessionHttpReconstruction.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <optional>
#include <span>

#include "app/session/CaptureSession.h"
#include "core/reassembly/ReassemblyTypes.h"
namespace pfl::session_detail {

namespace {

struct ReassembledPayloadChunk {
    std::uint64_t packet_index {0};
    std::size_t byte_count {0};
};

struct ParsedHttpHeaderBlock {
    std::size_t size {0U};
    std::string label {};
    HttpStreamItemSummaryDetails summary {};
};

std::string_view bytes_as_text(std::span<const std::uint8_t> bytes) {
    return std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

bool ascii_iequals(const char left, const char right) noexcept {
    return std::tolower(static_cast<unsigned char>(left)) == std::tolower(static_cast<unsigned char>(right));
}

bool starts_with_ascii_case_insensitive(const std::string_view value, const std::string_view prefix) noexcept {
    if (value.size() < prefix.size()) {
        return false;
    }

    for (std::size_t index = 0U; index < prefix.size(); ++index) {
        if (!ascii_iequals(value[index], prefix[index])) {
            return false;
        }
    }

    return true;
}

std::string trim_ascii(const std::string_view value) {
    std::size_t begin = 0U;
    std::size_t end = value.size();

    while (begin < end && (value[begin] == ' ' || value[begin] == '\t' || value[begin] == '\r' || value[begin] == '\n')) {
        ++begin;
    }

    while (end > begin && (value[end - 1U] == ' ' || value[end - 1U] == '\t' || value[end - 1U] == '\r' || value[end - 1U] == '\n')) {
        --end;
    }

    return std::string {value.substr(begin, end - begin)};
}

bool is_http_token_char(const char value) noexcept {
    return std::isalnum(static_cast<unsigned char>(value)) != 0 || value == '-' || value == '_' || value == '.' || value == '/';
}

std::size_t http_line_end(const std::string_view text, const std::size_t offset) noexcept {
    const auto crlf = text.find("\r\n", offset);
    const auto lf = text.find('\n', offset);
    if (crlf == std::string_view::npos) {
        return lf;
    }
    if (lf == std::string_view::npos) {
        return crlf;
    }
    return (crlf < lf) ? crlf : lf;
}

std::size_t http_next_line_offset(const std::string_view text, const std::size_t end) noexcept {
    if (end == std::string_view::npos || end >= text.size()) {
        return text.size();
    }

    if (text[end] == '\r' && (end + 1U) < text.size() && text[end + 1U] == '\n') {
        return end + 2U;
    }

    return end + 1U;
}

std::optional<std::size_t> http_header_block_size(std::string_view payload_text, const std::size_t offset) noexcept {
    if (offset >= payload_text.size()) {
        return std::nullopt;
    }

    const auto subtext = payload_text.substr(offset);
    const auto crlfcrlf = subtext.find("\r\n\r\n");
    const auto lflf = subtext.find("\n\n");
    if (crlfcrlf == std::string_view::npos && lflf == std::string_view::npos) {
        return std::nullopt;
    }

    if (crlfcrlf != std::string_view::npos && (lflf == std::string_view::npos || crlfcrlf < lflf)) {
        return crlfcrlf + 4U;
    }

    return lflf + 2U;
}

bool looks_like_http_request_line(const std::string_view line) noexcept {
    constexpr std::array<std::string_view, 9> methods {
        "GET ", "POST ", "PUT ", "HEAD ", "OPTIONS ", "DELETE ", "PATCH ", "CONNECT ", "TRACE ",
    };

    for (const auto method : methods) {
        if (line.starts_with(method)) {
            return true;
        }
    }

    return false;
}

bool looks_like_http_response_line(const std::string_view line) noexcept {
    return line.starts_with("HTTP/1.");
}

std::optional<std::string> extract_http_header_value(
    const std::string_view headers,
    const std::string_view header_name
) {
    std::size_t offset = 0U;
    while (offset < headers.size()) {
        const auto end = http_line_end(headers, offset);
        const auto line = headers.substr(offset, ((end == std::string_view::npos) ? headers.size() : end) - offset);
        if (line.empty()) {
            break;
        }

        const auto separator = line.find(':');
        if (separator != std::string_view::npos) {
            const auto name = trim_ascii(line.substr(0U, separator));
            if (starts_with_ascii_case_insensitive(name, header_name) && name.size() == header_name.size()) {
                const auto value = trim_ascii(line.substr(separator + 1U));
                if (!value.empty()) {
                    return value;
                }
                return std::nullopt;
            }
        }

        if (end == std::string_view::npos) {
            break;
        }
        offset = http_next_line_offset(headers, end);
    }

    return std::nullopt;
}

std::optional<std::size_t> parse_http_size_value(
    const std::string_view text,
    const int base
) noexcept {
    const auto value = trim_ascii(text);
    if (value.empty()) {
        return std::nullopt;
    }

    try {
        std::size_t parsed_characters = 0U;
        const auto parsed = std::stoull(value, &parsed_characters, base);
        if (parsed_characters != value.size() || parsed > std::numeric_limits<std::size_t>::max()) {
            return std::nullopt;
        }
        return static_cast<std::size_t>(parsed);
    } catch (...) {
        return std::nullopt;
    }
}

bool http_header_value_contains_token(
    const std::string_view value,
    const std::string_view token
) noexcept {
    std::size_t offset = 0U;
    while (offset < value.size()) {
        const auto separator = value.find(',', offset);
        const auto part = trim_ascii(value.substr(offset, (separator == std::string_view::npos) ? (value.size() - offset) : (separator - offset)));
        if (part.size() == token.size() && starts_with_ascii_case_insensitive(part, token)) {
            return true;
        }
        if (separator == std::string_view::npos) {
            break;
        }
        offset = separator + 1U;
    }
    return false;
}

std::optional<std::size_t> complete_http_chunked_body_size(
    const std::string_view payload_text,
    const std::size_t body_offset
) noexcept {
    std::size_t cursor = body_offset;
    while (cursor < payload_text.size()) {
        const auto line_end = http_line_end(payload_text, cursor);
        if (line_end == std::string_view::npos) {
            return std::nullopt;
        }

        const auto chunk_line = payload_text.substr(cursor, line_end - cursor);
        const auto extension_separator = chunk_line.find(';');
        const auto chunk_size_text = trim_ascii(chunk_line.substr(0U, extension_separator));
        const auto chunk_size = parse_http_size_value(chunk_size_text, 16);
        if (!chunk_size.has_value()) {
            return std::nullopt;
        }

        cursor = http_next_line_offset(payload_text, line_end);
        if (*chunk_size == 0U) {
            while (cursor <= payload_text.size()) {
                const auto trailer_end = http_line_end(payload_text, cursor);
                if (trailer_end == std::string_view::npos) {
                    return std::nullopt;
                }
                const auto trailer_line = payload_text.substr(cursor, trailer_end - cursor);
                cursor = http_next_line_offset(payload_text, trailer_end);
                if (trailer_line.empty()) {
                    return cursor - body_offset;
                }
            }
            return std::nullopt;
        }

        if (*chunk_size > (payload_text.size() - cursor)) {
            return std::nullopt;
        }
        cursor += *chunk_size;

        if (cursor >= payload_text.size()) {
            return std::nullopt;
        }
        if (payload_text[cursor] == '\r') {
            if ((cursor + 1U) >= payload_text.size() || payload_text[cursor + 1U] != '\n') {
                return std::nullopt;
            }
            cursor += 2U;
        } else if (payload_text[cursor] == '\n') {
            cursor += 1U;
        } else {
            return std::nullopt;
        }
    }

    return std::nullopt;
}

std::size_t http_message_size(
    const std::string_view payload_text,
    const std::size_t offset,
    const std::size_t header_size,
    const std::string_view headers_text
) noexcept {
    const auto body_offset = offset + header_size;
    if (body_offset > payload_text.size()) {
        return header_size;
    }

    if (const auto transfer_encoding = extract_http_header_value(headers_text, "Transfer-Encoding");
        transfer_encoding.has_value() && http_header_value_contains_token(*transfer_encoding, "chunked")) {
        if (const auto body_size = complete_http_chunked_body_size(payload_text, body_offset); body_size.has_value()) {
            return header_size + *body_size;
        }
        return header_size;
    }

    if (const auto content_length = extract_http_header_value(headers_text, "Content-Length"); content_length.has_value()) {
        if (const auto body_size = parse_http_size_value(*content_length, 10); body_size.has_value() && *body_size <= (payload_text.size() - body_offset)) {
            return header_size + *body_size;
        }
    }

    return header_size;
}

std::optional<ParsedHttpHeaderBlock> parse_http_header_block(
    std::span<const std::uint8_t> payload_bytes,
    const std::size_t offset
) {
    const auto payload_text = bytes_as_text(payload_bytes);
    const auto header_size = http_header_block_size(payload_text, offset);
    if (!header_size.has_value()) {
        return std::nullopt;
    }

    const auto header_text = payload_text.substr(offset, *header_size);
    const auto first_line_end = http_line_end(header_text, 0U);
    const auto first_line = header_text.substr(0U, (first_line_end == std::string_view::npos) ? header_text.size() : first_line_end);
    if (first_line.empty()) {
        return std::nullopt;
    }
    const auto headers_text = header_text.substr(http_next_line_offset(header_text, first_line_end));

    if (looks_like_http_request_line(first_line)) {
        const auto method_end = first_line.find(' ');
        if (method_end == std::string_view::npos) {
            return std::nullopt;
        }

        const auto path_start = method_end + 1U;
        const auto path_end = first_line.find(' ', path_start);
        if (path_end == std::string_view::npos || path_end <= path_start) {
            return std::nullopt;
        }

        const auto method = first_line.substr(0U, method_end);
        const auto path = first_line.substr(path_start, path_end - path_start);
        const auto version = first_line.substr(path_end + 1U);
        if (!version.starts_with("HTTP/1.") || path.empty()) {
            return std::nullopt;
        }

        for (const auto character : method) {
            if (!std::isupper(static_cast<unsigned char>(character))) {
                return std::nullopt;
            }
        }
        for (const auto character : version) {
            if (!(is_http_token_char(character) || character == ' ')) {
                return std::nullopt;
            }
        }

        const auto method_text = std::string {method};
        const auto path_text = std::string {path};
        const auto summary = HttpStreamItemSummaryDetails {
            .semantic_kind = HttpStreamItemSemanticKind::request,
            .method = method_text,
            .target = path_text,
            .version = std::string {version},
        };
        return ParsedHttpHeaderBlock {
            .size = http_message_size(payload_text, offset, *header_size, headers_text),
            .label = http_stream_label_from_summary(summary),
            .summary = summary,
        };
    }

    if (looks_like_http_response_line(first_line)) {
        const auto version_end = first_line.find(' ');
        if (version_end == std::string_view::npos) {
            return std::nullopt;
        }

        const auto code_start = version_end + 1U;
        if (code_start + 3U > first_line.size()) {
            return std::nullopt;
        }

        const auto version = first_line.substr(0U, version_end);
        const auto code = first_line.substr(code_start, 3U);
        for (const auto character : code) {
            if (!std::isdigit(static_cast<unsigned char>(character))) {
                return std::nullopt;
            }
        }

        std::string reason_text {};
        const auto reason_start = code_start + 3U;
        if (reason_start < first_line.size() && first_line[reason_start] == ' ') {
            const auto reason = trim_ascii(first_line.substr(reason_start + 1U));
            if (!reason.empty()) {
                reason_text = reason;
            }
        }

        const auto code_text = std::string {code};
        const auto status_code = static_cast<std::uint16_t>(std::stoi(code_text));
        const auto summary = HttpStreamItemSummaryDetails {
            .semantic_kind = HttpStreamItemSemanticKind::response,
            .version = std::string {version},
            .status_code = status_code,
            .reason_phrase = reason_text,
        };
        return ParsedHttpHeaderBlock {
            .size = http_message_size(payload_text, offset, *header_size, headers_text),
            .label = http_stream_label_from_summary(summary),
            .summary = summary,
        };
    }

    return std::nullopt;
}

std::optional<std::vector<ReassembledPayloadChunk>> build_reassembled_payload_chunks(
    const ReassemblyResult& result
) {
    if (result.packet_indices.size() != result.packet_byte_counts.size()) {
        return std::nullopt;
    }

    std::vector<ReassembledPayloadChunk> chunks {};
    chunks.reserve(result.packet_indices.size());
    std::size_t consumed_bytes = 0U;

    for (std::size_t index = 0U; index < result.packet_indices.size(); ++index) {
        if (consumed_bytes >= result.bytes.size()) {
            break;
        }

        const auto remaining_bytes = result.bytes.size() - consumed_bytes;
        const auto chunk_size = std::min<std::size_t>(result.packet_byte_counts[index], remaining_bytes);
        if (chunk_size == 0U) {
            continue;
        }

        chunks.push_back(ReassembledPayloadChunk {
            .packet_index = result.packet_indices[index],
            .byte_count = chunk_size,
        });
        consumed_bytes += chunk_size;
    }

    if (consumed_bytes != result.bytes.size()) {
        return std::nullopt;
    }

    return chunks;
}

std::vector<std::uint64_t> consume_reassembled_packet_indices(
    const std::vector<ReassembledPayloadChunk>& chunks,
    const std::size_t byte_count,
    std::size_t& chunk_index,
    std::size_t& chunk_offset
) {
    std::vector<std::uint64_t> packet_indices {};
    std::size_t remaining_bytes = byte_count;

    while (remaining_bytes > 0U && chunk_index < chunks.size()) {
        const auto& chunk = chunks[chunk_index];
        if (packet_indices.empty() || packet_indices.back() != chunk.packet_index) {
            packet_indices.push_back(chunk.packet_index);
        }

        const auto chunk_remaining = chunk.byte_count - chunk_offset;
        const auto consumed_here = std::min(remaining_bytes, chunk_remaining);
        remaining_bytes -= consumed_here;
        chunk_offset += consumed_here;

        if (chunk_offset >= chunk.byte_count) {
            ++chunk_index;
            chunk_offset = 0U;
        }
    }

    return packet_indices;
}

bool append_bounded_http_item(
    HttpDirectionalStreamPresentation& presentation,
    HttpStreamPresentationItem item,
    std::size_t& logical_item_count,
    const std::size_t skip_item_count,
    const std::size_t max_item_count
) {
    if (logical_item_count >= skip_item_count && presentation.items.size() < max_item_count) {
        presentation.items.push_back(std::move(item));
    }
    ++logical_item_count;
    return presentation.items.size() < max_item_count;
}

}  // namespace

std::string http_stream_label_from_summary(const HttpStreamItemSummaryDetails& summary) {
    switch (summary.semantic_kind) {
    case HttpStreamItemSemanticKind::request:
        if (!summary.method.empty() && !summary.target.empty()) {
            return "HTTP " + summary.method + " " + summary.target;
        }
        return "HTTP Request";
    case HttpStreamItemSemanticKind::response:
        if (summary.status_code.has_value()) {
            const auto code = std::to_string(*summary.status_code);
            return summary.reason_phrase.empty()
                ? "HTTP " + code
                : "HTTP " + code + " " + summary.reason_phrase;
        }
        return "HTTP Response";
    case HttpStreamItemSemanticKind::partial_payload:
        return "HTTP Payload (partial)";
    case HttpStreamItemSemanticKind::gap:
        return "HTTP Gap";
    case HttpStreamItemSemanticKind::none:
    default:
        return "HTTP Payload";
    }
}

HttpDirectionalStreamPresentation build_http_stream_items_from_reassembly(
    const CaptureSession& session,
    const std::size_t flow_index,
    const Direction direction,
    const std::span<const PacketRef> direction_packets
) {
    return build_http_stream_items_from_reassembly_bounded(
        session,
        flow_index,
        direction,
        direction_packets,
        0U,
        std::numeric_limits<std::size_t>::max()
    );
}

HttpDirectionalStreamPresentation build_http_stream_items_from_reassembly_bounded(
    const CaptureSession& session,
    const std::size_t flow_index,
    const Direction direction,
    const std::span<const PacketRef> direction_packets,
    const std::size_t skip_item_count,
    const std::size_t max_item_count
) {
    HttpDirectionalStreamPresentation presentation {};
    if (max_item_count == 0U) {
        return presentation;
    }

    constexpr std::size_t kHttpReassemblyMaxBytes = 2U * 1024U * 1024U;

    const auto result = session.reassemble_flow_direction(
        ReassemblyRequest {
            .flow_index = flow_index,
            .direction = direction,
            .max_packets = direction_packets.size(),
            .max_bytes = kHttpReassemblyMaxBytes,
        },
        direction_packets
    );
    if (!result.has_value() || result->bytes.empty()) {
        return presentation;
    }

    const auto payload_bytes = std::span<const std::uint8_t>(result->bytes.data(), result->bytes.size());
    const auto payload_text = bytes_as_text(payload_bytes);
    const auto chunks = build_reassembled_payload_chunks(*result);
    if (!chunks.has_value() || chunks->empty()) {
        return presentation;
    }

    std::size_t offset = 0U;
    std::size_t chunk_index = 0U;
    std::size_t chunk_offset = 0U;
    std::size_t logical_item_count = 0U;
    bool emitted_any = false;

    while (offset < payload_bytes.size()) {
        const auto parsed = parse_http_header_block(payload_bytes, offset);
        if (!parsed.has_value()) {
            if (offset == 0U) {
                return presentation;
            }

            const auto trailing = payload_bytes.subspan(offset);
            if (!trailing.empty()) {
                const auto should_continue = append_bounded_http_item(
                    presentation,
                    HttpStreamPresentationItem {
                    .label = "HTTP Payload (partial)",
                    .byte_count = trailing.size(),
                    .packet_indices = consume_reassembled_packet_indices(*chunks, trailing.size(), chunk_index, chunk_offset),
                    .stability = StreamMaterializationStability::window_incomplete,
                    .summary = HttpStreamItemSummaryDetails {
                        .semantic_kind = HttpStreamItemSemanticKind::partial_payload,
                        .diagnostic = "Window ended before a complete HTTP header block was available.",
                    },
                    },
                    logical_item_count,
                    skip_item_count,
                    max_item_count
                );
                if (!should_continue) {
                    presentation.used_reassembly = true;
                    break;
                }
            }
            presentation.used_reassembly = true;
            break;
        }

        const auto block_bytes = payload_bytes.subspan(offset, parsed->size);
        const auto should_continue = append_bounded_http_item(
            presentation,
            HttpStreamPresentationItem {
            .label = parsed->label,
            .byte_count = block_bytes.size(),
            .packet_indices = consume_reassembled_packet_indices(*chunks, block_bytes.size(), chunk_index, chunk_offset),
            .summary = parsed->summary,
            },
            logical_item_count,
            skip_item_count,
            max_item_count
        );
        emitted_any = true;
        offset += parsed->size;
        if (!should_continue) {
            break;
        }

        if (offset < payload_text.size()) {
            const auto next_line_end = http_line_end(payload_text, offset);
            const auto next_line = payload_text.substr(offset, ((next_line_end == std::string_view::npos) ? payload_text.size() : next_line_end) - offset);
            if (!looks_like_http_request_line(next_line) && !looks_like_http_response_line(next_line)) {
                const auto trailing = payload_bytes.subspan(offset);
                if (!trailing.empty()) {
                    const auto should_continue_after_trailing = append_bounded_http_item(
                        presentation,
                        HttpStreamPresentationItem {
                        .label = "HTTP Payload (partial)",
                        .byte_count = trailing.size(),
                        .packet_indices = consume_reassembled_packet_indices(*chunks, trailing.size(), chunk_index, chunk_offset),
                        .stability = StreamMaterializationStability::window_incomplete,
                        .summary = HttpStreamItemSummaryDetails {
                            .semantic_kind = HttpStreamItemSemanticKind::partial_payload,
                            .diagnostic = "A later HTTP message boundary was not available in the loaded reassembly window.",
                        },
                        },
                        logical_item_count,
                        skip_item_count,
                        max_item_count
                    );
                    if (!should_continue_after_trailing) {
                        presentation.used_reassembly = true;
                        break;
                    }
                }
                presentation.used_reassembly = true;
                break;
            }
        }
    }

    presentation.used_reassembly = presentation.used_reassembly || emitted_any;
    if (presentation.used_reassembly) {
        presentation.covered_packet_indices.insert(result->packet_indices.begin(), result->packet_indices.end());
    }
    if (result->stopped_at_gap && result->first_gap_packet_index != 0U) {
        append_bounded_http_item(
            presentation,
            HttpStreamPresentationItem {
            .label = "HTTP Gap",
            .byte_count = 0U,
            .packet_indices = std::vector<std::uint64_t> {result->first_gap_packet_index},
            .summary = HttpStreamItemSummaryDetails {
                .semantic_kind = HttpStreamItemSemanticKind::gap,
                .diagnostic = "Earlier TCP bytes are missing, so later HTTP bytes are shown conservatively.",
            },
            },
            logical_item_count,
            skip_item_count,
            max_item_count
        );
        presentation.used_reassembly = true;
        presentation.explicit_gap_item_emitted = true;
        presentation.first_gap_packet_index = result->first_gap_packet_index;
        presentation.fallback_label = "HTTP Payload";
    }

    return presentation;
}

}  // namespace pfl::session_detail
