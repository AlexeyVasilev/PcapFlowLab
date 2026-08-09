#include "app/frontend/FrontendSettingsJson.h"

#include <cctype>
#include <fstream>
#include <iterator>
#include <optional>
#include <string_view>
#include <utility>

namespace pfl {
namespace {

class JsonCursor {
public:
    explicit JsonCursor(std::string text)
        : text_(std::move(text)) {}

    [[nodiscard]] bool at_end() const noexcept {
        return index_ >= text_.size();
    }

    [[nodiscard]] std::size_t index() const noexcept {
        return index_;
    }

    void skip_whitespace() noexcept {
        while (!at_end() && std::isspace(static_cast<unsigned char>(text_[index_])) != 0) {
            ++index_;
        }
    }

    [[nodiscard]] bool consume(const char expected) noexcept {
        skip_whitespace();
        if (at_end() || text_[index_] != expected) {
            return false;
        }
        ++index_;
        return true;
    }

    [[nodiscard]] std::optional<std::string> parse_string() {
        skip_whitespace();
        if (at_end() || text_[index_] != '"') {
            return std::nullopt;
        }

        ++index_;
        std::string value {};
        while (!at_end()) {
            const auto ch = text_[index_++];
            if (ch == '"') {
                return value;
            }
            if (ch == '\\') {
                if (at_end()) {
                    return std::nullopt;
                }
                const auto escaped = text_[index_++];
                switch (escaped) {
                case '"':
                case '\\':
                case '/':
                    value.push_back(escaped);
                    break;
                case 'b':
                    value.push_back('\b');
                    break;
                case 'f':
                    value.push_back('\f');
                    break;
                case 'n':
                    value.push_back('\n');
                    break;
                case 'r':
                    value.push_back('\r');
                    break;
                case 't':
                    value.push_back('\t');
                    break;
                default:
                    return std::nullopt;
                }
                continue;
            }
            if (static_cast<unsigned char>(ch) < 0x20U) {
                return std::nullopt;
            }
            value.push_back(ch);
        }

        return std::nullopt;
    }

    [[nodiscard]] std::optional<bool> parse_bool() noexcept {
        skip_whitespace();
        if (text_.compare(index_, 4U, "true") == 0) {
            index_ += 4U;
            return true;
        }
        if (text_.compare(index_, 5U, "false") == 0) {
            index_ += 5U;
            return false;
        }
        return std::nullopt;
    }

private:
    std::string text_ {};
    std::size_t index_ {0U};
};

std::string parse_error_prefix(const JsonCursor& cursor) {
    return "Invalid settings JSON near byte " + std::to_string(cursor.index()) + ": ";
}

}  // namespace

FrontendSettingsJsonParseResult parse_frontend_settings_json_file(const std::filesystem::path& path) {
    FrontendSettingsJsonParseResult result {};

    if (path.empty()) {
        result.error_text = "No settings file selected.";
        return result;
    }

    std::ifstream stream {path, std::ios::binary};
    if (!stream.is_open()) {
        result.error_text = "Failed to open settings file: " + path.string();
        return result;
    }

    const std::string text {
        std::istreambuf_iterator<char>(stream),
        std::istreambuf_iterator<char>()
    };
    if (!stream.good() && !stream.eof()) {
        result.error_text = "Failed to read settings file: " + path.string();
        return result;
    }

    JsonCursor cursor {text};
    if (!cursor.consume('{')) {
        result.error_text = parse_error_prefix(cursor) + "expected top-level object.";
        return result;
    }

    FrontendSettingsDto settings {};
    bool expect_member = true;
    bool object_empty = true;
    while (true) {
        cursor.skip_whitespace();
        if (cursor.consume('}')) {
            if (expect_member && !object_empty) {
                result.error_text = parse_error_prefix(cursor) + "expected string property name.";
                return result;
            }
            break;
        }
        if (!expect_member) {
            result.error_text = parse_error_prefix(cursor) + "expected ',' or '}'.";
            return result;
        }
        expect_member = false;
        object_empty = false;

        const auto key = cursor.parse_string();
        if (!key.has_value()) {
            result.error_text = parse_error_prefix(cursor) + "expected string property name.";
            return result;
        }
        if (!cursor.consume(':')) {
            result.error_text = parse_error_prefix(cursor) + "expected ':'.";
            return result;
        }

        const auto value = cursor.parse_bool();
        if (!value.has_value()) {
            result.error_text = parse_error_prefix(cursor)
                + "expected boolean value for setting '" + *key + "'.";
            return result;
        }

        if (*key == "ignore_vlan_and_mpls_layers_when_grouping_flows") {
            settings.ignore_vlan_and_mpls_layers_when_grouping_flows = *value;
        } else if (*key == "ignore_gtpu_teids_when_grouping_inner_flows") {
            settings.ignore_gtpu_teids_when_grouping_inner_flows = *value;
        } else if (*key == "validate_selected_packet_checksums") {
            settings.validate_selected_packet_checksums = *value;
        } else {
            result.error_text = "Unknown settings field: " + *key;
            return result;
        }

        cursor.skip_whitespace();
        if (cursor.consume('}')) {
            break;
        }
        if (!cursor.consume(',')) {
            result.error_text = parse_error_prefix(cursor) + "expected ',' or '}'.";
            return result;
        }
        expect_member = true;
    }

    cursor.skip_whitespace();
    if (!cursor.at_end()) {
        result.error_text = parse_error_prefix(cursor) + "unexpected trailing content.";
        return result;
    }

    result.ok = true;
    result.settings = settings;
    return result;
}

}  // namespace pfl
