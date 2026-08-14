#include "app/frontend/FrontendSessionAdapter.h"
#include "app/session/SupportedProtocolCatalog.h"

#include "TestSupport.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace pfl::tests {

namespace {

std::filesystem::path repo_root() {
    return std::filesystem::path(__FILE__).parent_path().parent_path().parent_path();
}

std::string read_text_file(const std::filesystem::path& path) {
    std::ifstream stream {path, std::ios::binary};
    if (!stream.is_open()) {
        return {};
    }

    std::ostringstream out {};
    out << stream.rdbuf();
    return out.str();
}

std::string normalize_text(std::string text) {
    std::string normalized {};
    normalized.reserve(text.size());

    for (std::size_t index = 0; index < text.size(); ++index) {
        if (text[index] == '\r') {
            if (index + 1U < text.size() && text[index + 1U] == '\n') {
                continue;
            }
            normalized.push_back('\n');
            continue;
        }
        normalized.push_back(text[index]);
    }

    while (!normalized.empty() && std::isspace(static_cast<unsigned char>(normalized.front())) != 0) {
        normalized.erase(normalized.begin());
    }
    while (!normalized.empty() && std::isspace(static_cast<unsigned char>(normalized.back())) != 0) {
        normalized.pop_back();
    }

    return normalized;
}

const session_detail::SupportedProtocolCatalogRow* find_row(const std::string_view stable_id) {
    const auto rows = session_detail::supported_protocol_catalog_rows();
    const auto it = std::find_if(rows.begin(), rows.end(), [stable_id](const auto& row) {
        return row.stable_id == stable_id;
    });
    return it == rows.end() ? nullptr : &*it;
}

std::optional<std::string> extract_marked_block(
    const std::string& document,
    const std::string_view begin_marker,
    const std::string_view end_marker
) {
    const auto begin = document.find(begin_marker);
    const auto end = document.find(end_marker);
    if (begin == std::string::npos || end == std::string::npos || end < begin) {
        return std::nullopt;
    }

    const auto content_begin = begin + begin_marker.size();
    return document.substr(content_begin, end - content_begin);
}

void expect_catalog_row_contracts() {
    const auto rows = session_detail::supported_protocol_catalog_rows();
    PFL_EXPECT(rows.size() == 35U);

    std::set<std::string> ids {};
    for (const auto& row : rows) {
        PFL_EXPECT(!row.stable_id.empty());
        PFL_EXPECT(ids.insert(std::string {row.stable_id}).second);
    }

    const std::vector<session_detail::SupportedProtocolCategory> expected_category_order {
        session_detail::SupportedProtocolCategory::link_and_encapsulation,
        session_detail::SupportedProtocolCategory::network,
        session_detail::SupportedProtocolCategory::transport,
        session_detail::SupportedProtocolCategory::tunnels_and_overlays,
        session_detail::SupportedProtocolCategory::security,
        session_detail::SupportedProtocolCategory::application,
    };

    std::vector<session_detail::SupportedProtocolCategory> category_order {};
    for (const auto& row : rows) {
        if (category_order.empty() || category_order.back() != row.category) {
            category_order.push_back(row.category);
        }
    }
    PFL_EXPECT(category_order == expected_category_order);
}

void expect_status_descriptor_contracts() {
    const auto descriptors = session_detail::supported_protocol_status_descriptors();
    PFL_REQUIRE(descriptors.size() == 4U);
    PFL_EXPECT(descriptors[0].stable_id == "yes");
    PFL_EXPECT(descriptors[1].stable_id == "partial");
    PFL_EXPECT(descriptors[2].stable_id == "no");
    PFL_EXPECT(descriptors[3].stable_id == "not_applicable");
    PFL_EXPECT(descriptors[3].display_label == "N/A");
}

void expect_representative_rows() {
    const auto* tls = find_row("tls");
    PFL_REQUIRE(tls != nullptr);
    PFL_EXPECT(tls->service == session_detail::SupportedProtocolCapabilityStatus::partial);
    PFL_EXPECT(tls->packet_summary == session_detail::SupportedProtocolCapabilityStatus::yes);

    const auto* quic = find_row("quic");
    PFL_REQUIRE(quic != nullptr);
    PFL_EXPECT(quic->packet_summary == session_detail::SupportedProtocolCapabilityStatus::partial);
    PFL_EXPECT(quic->stream == session_detail::SupportedProtocolCapabilityStatus::partial);

    const auto* http = find_row("http");
    PFL_REQUIRE(http != nullptr);
    PFL_EXPECT(http->protocol == "HTTP/1.x");
    PFL_EXPECT(http->service == session_detail::SupportedProtocolCapabilityStatus::yes);
    PFL_EXPECT(http->stream == session_detail::SupportedProtocolCapabilityStatus::yes);

    const auto* macsec = find_row("macsec");
    PFL_REQUIRE(macsec != nullptr);
    PFL_EXPECT(macsec->recognition == session_detail::SupportedProtocolCapabilityStatus::partial);
    PFL_EXPECT(macsec->packet_summary == session_detail::SupportedProtocolCapabilityStatus::partial);

    const auto* tcp = find_row("tcp");
    PFL_REQUIRE(tcp != nullptr);
    PFL_EXPECT(tcp->stream == session_detail::SupportedProtocolCapabilityStatus::partial);

    const auto* sctp = find_row("sctp");
    PFL_REQUIRE(sctp != nullptr);
    PFL_EXPECT(sctp->stream == session_detail::SupportedProtocolCapabilityStatus::no);

    const auto* ssh = find_row("ssh");
    PFL_REQUIRE(ssh != nullptr);
    PFL_EXPECT(ssh->recognition == session_detail::SupportedProtocolCapabilityStatus::yes);
    PFL_EXPECT(ssh->stream == session_detail::SupportedProtocolCapabilityStatus::no);

    const auto* dhcp = find_row("dhcp");
    PFL_REQUIRE(dhcp != nullptr);
    PFL_EXPECT(dhcp->protocol == "DHCPv4");
}

void expect_markdown_escaping() {
    const std::vector<session_detail::SupportedProtocolCatalogRow> custom_rows {
        {
            "escape_probe",
            "Proto | Backslash \\",
            session_detail::SupportedProtocolCategory::application,
            session_detail::SupportedProtocolCapabilityStatus::yes,
            session_detail::SupportedProtocolCapabilityStatus::no,
            session_detail::SupportedProtocolCapabilityStatus::partial,
            session_detail::SupportedProtocolCapabilityStatus::not_applicable,
            "Pipe | slash \\ preserved",
        },
    };

    const auto rendered = session_detail::render_supported_protocol_catalog_markdown_table(custom_rows);
    PFL_EXPECT(rendered.find("Proto \\| Backslash \\\\") != std::string::npos);
    PFL_EXPECT(rendered.find("Pipe \\| slash \\\\ preserved") != std::string::npos);
}

void expect_frontend_catalog_exposure_without_capture() {
    FrontendSessionAdapter adapter {};
    const auto catalog = adapter.get_supported_protocol_catalog();
    PFL_EXPECT(catalog.rows.size() == 35U);
    PFL_REQUIRE(!catalog.rows.empty());
    PFL_EXPECT(catalog.rows.front().category_id == "link_and_encapsulation");
    PFL_EXPECT(catalog.rows.front().recognition_status_id == "yes");
    PFL_EXPECT(catalog.rows.back().protocol_id == "mail_protocols");
}

void expect_protocol_support_document_sync() {
    const auto document_path = repo_root() / "docs" / "protocols" / "protocol_support.md";
    const auto document_text = read_text_file(document_path);
    PFL_REQUIRE(!document_text.empty());

    const auto extracted = extract_marked_block(
        document_text,
        session_detail::kSupportedProtocolCatalogBeginMarker,
        session_detail::kSupportedProtocolCatalogEndMarker
    );
    PFL_REQUIRE(extracted.has_value());

    const auto expected = normalize_text(session_detail::render_supported_protocol_catalog_markdown_table());
    const auto actual = normalize_text(*extracted);
    if (actual != expected) {
        record_failure_message(
            "SupportedProtocolCatalog and docs/protocols/protocol_support.md must be updated together."
        );
    }
    PFL_EXPECT(actual == expected);
}

}  // namespace

void run_supported_protocol_catalog_tests() {
    expect_catalog_row_contracts();
    expect_status_descriptor_contracts();
    expect_representative_rows();
    expect_markdown_escaping();
    expect_frontend_catalog_exposure_without_capture();
    expect_protocol_support_document_sync();
}

}  // namespace pfl::tests
