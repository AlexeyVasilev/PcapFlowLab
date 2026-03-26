#include "core/services/HttpPacketProtocolAnalyzer.h"

#include <array>
#include <cctype>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>

#include "core/services/PacketPayloadService.h"

namespace pfl {

namespace {

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

    for (std::size_t index = 0; index < prefix.size(); ++index) {
        if (!ascii_iequals(value[index], prefix[index])) {
            return false;
        }
    }

    return true;
}

std::string trim_ascii(const std::string_view value) {
    std::size_t begin = 0;
    std::size_t end = value.size();

    while (begin < end && (value[begin] == ' ' || value[begin] == '\t' || value[begin] == '\r' || value[begin] == '\n')) {
        ++begin;
    }

    while (end > begin && (value[end - 1] == ' ' || value[end - 1] == '\t' || value[end - 1] == '\r' || value[end - 1] == '\n')) {
        --end;
    }

    return std::string(value.substr(begin, end - begin));
}

bool is_http_token_char(const char value) noexcept {
    return std::isalnum(static_cast<unsigned char>(value)) != 0 || value == '-' || value == '_' || value == '.' || value == '/';
}

bool is_plausible_host_char(const char value) noexcept {
    return std::isalnum(static_cast<unsigned char>(value)) != 0 || value == '.' || value == '-' || value == '_';
}

bool is_plausible_host(const std::string_view value) noexcept {
    if (value.empty()) {
        return false;
    }

    for (const auto character : value) {
        if (!is_plausible_host_char(character)) {
            return false;
        }
    }

    return true;
}

std::size_t header_block_end(const std::string_view payload_text) noexcept {
    const auto crlfcrlf = payload_text.find("\r\n\r\n");
    if (crlfcrlf != std::string_view::npos) {
        return crlfcrlf;
    }

    return payload_text.find("\n\n");
}

std::size_t line_end(const std::string_view text, const std::size_t offset) noexcept {
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

std::size_t next_line_offset(const std::string_view text, const std::size_t end) noexcept {
    if (end == std::string_view::npos || end >= text.size()) {
        return text.size();
    }

    if (text[end] == '\r' && (end + 1U) < text.size() && text[end + 1U] == '\n') {
        return end + 2U;
    }

    return end + 1U;
}

bool looks_like_http_request(const std::string_view line) noexcept {
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

bool looks_like_http_response(const std::string_view line) noexcept {
    return line.starts_with("HTTP/1.");
}

std::optional<std::string> extract_host_header(const std::string_view headers) {
    std::size_t offset = 0;
    while (offset < headers.size()) {
        const auto end = line_end(headers, offset);
        const auto line = headers.substr(offset, ((end == std::string_view::npos) ? headers.size() : end) - offset);
        if (line.empty()) {
            break;
        }

        if (starts_with_ascii_case_insensitive(line, "Host:")) {
            const auto host = trim_ascii(line.substr(5));
            if (is_plausible_host(host)) {
                return host;
            }
            return std::nullopt;
        }

        if (end == std::string_view::npos) {
            break;
        }
        offset = next_line_offset(headers, end);
    }

    return std::nullopt;
}

}  // namespace

std::optional<std::string> HttpPacketProtocolAnalyzer::analyze(std::span<const std::uint8_t> packet_bytes) const {
    PacketPayloadService payload_service {};
    const auto payload_bytes = payload_service.extract_transport_payload(packet_bytes);
    if (payload_bytes.empty()) {
        return std::nullopt;
    }

    const auto payload_text = bytes_as_text(std::span<const std::uint8_t>(payload_bytes.data(), payload_bytes.size()));
    const auto headers_end = header_block_end(payload_text);
    if (headers_end == std::string_view::npos) {
        return std::nullopt;
    }

    const auto headers = payload_text.substr(0, headers_end);
    const auto first_line_end = line_end(headers, 0);
    const auto first_line = headers.substr(0, (first_line_end == std::string_view::npos) ? headers.size() : first_line_end);
    if (first_line.empty()) {
        return std::nullopt;
    }

    std::ostringstream text {};
    text << "HTTP\n";

    if (looks_like_http_request(first_line)) {
        const auto method_end = first_line.find(' ');
        if (method_end == std::string_view::npos) {
            return std::nullopt;
        }

        const auto path_start = method_end + 1U;
        const auto path_end = first_line.find(' ', path_start);
        if (path_end == std::string_view::npos || path_end <= path_start) {
            return std::nullopt;
        }

        const auto method = first_line.substr(0, method_end);
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

        text << "  Message Type: Request\n"
             << "  Method: " << method << "\n"
             << "  Path: " << path << "\n"
             << "  Version: " << version;

        const auto host = extract_host_header(headers.substr(next_line_offset(headers, first_line_end)));
        if (host.has_value()) {
            text << "\n"
                 << "  Host: " << *host;
        }

        return text.str();
    }

    if (looks_like_http_response(first_line)) {
        const auto version_end = first_line.find(' ');
        if (version_end == std::string_view::npos) {
            return std::nullopt;
        }

        const auto code_start = version_end + 1U;
        if (code_start + 3U > first_line.size()) {
            return std::nullopt;
        }

        const auto version = first_line.substr(0, version_end);
        const auto code = first_line.substr(code_start, 3U);
        for (const auto character : code) {
            if (!std::isdigit(static_cast<unsigned char>(character))) {
                return std::nullopt;
            }
        }

        text << "  Message Type: Response\n"
             << "  Version: " << version << "\n"
             << "  Status Code: " << code;

        const auto reason_start = code_start + 3U;
        if (reason_start < first_line.size() && first_line[reason_start] == ' ') {
            const auto reason = trim_ascii(first_line.substr(reason_start + 1U));
            if (!reason.empty()) {
                text << "\n"
                     << "  Reason: " << reason;
            }
        }

        return text.str();
    }

    return std::nullopt;
}

}  // namespace pfl
