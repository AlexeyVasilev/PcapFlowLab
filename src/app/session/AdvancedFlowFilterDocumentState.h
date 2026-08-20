#pragma once

#include <cstddef>
#include <filesystem>
#include <optional>

#include "app/session/AdvancedFlowFilter.h"

namespace pfl::session_detail {

class AdvancedFlowFilterDocumentState final {
public:
    AdvancedFlowFilterDocumentState() = default;

    [[nodiscard]] const AdvancedFlowFilterDocument& applied_document() const noexcept;
    [[nodiscard]] const AdvancedFlowFilterDocument* draft_document() const noexcept;
    [[nodiscard]] AdvancedFlowFilterDocument* draft_document() noexcept;
    [[nodiscard]] const AdvancedFlowFilterDocument& current_user_visible_document() const noexcept;
    [[nodiscard]] const AdvancedFlowFilterDocument* saved_baseline() const noexcept;
    [[nodiscard]] const std::filesystem::path* source_path() const noexcept;

    [[nodiscard]] bool is_editing() const noexcept;
    [[nodiscard]] bool is_file_backed() const noexcept;
    [[nodiscard]] bool has_unsaved_changes() const noexcept;
    [[nodiscard]] bool has_unsaved_configuration() const noexcept;
    [[nodiscard]] bool can_clear_unsaved_changes() const noexcept;
    [[nodiscard]] bool would_lose_unsaved_configuration() const noexcept;
    [[nodiscard]] std::size_t configured_rule_count() const noexcept;
    [[nodiscard]] std::size_t active_rule_count() const;

    void begin_edit();
    void cancel_edit() noexcept;
    [[nodiscard]] bool apply_draft();
    [[nodiscard]] bool revert_to_saved_baseline();
    void accept_opened_document(const AdvancedFlowFilterDocument& document, const std::filesystem::path& path);
    void accept_saved_document(const AdvancedFlowFilterDocument& document, const std::filesystem::path& path);
    void accept_custom_document(const AdvancedFlowFilterDocument& document);
    void clear_all();

private:
    void assert_invariant() const noexcept;
    void accept_file_backed_document(const AdvancedFlowFilterDocument& document, const std::filesystem::path& path);

    AdvancedFlowFilterDocument applied_document_ {};
    std::optional<AdvancedFlowFilterDocument> draft_document_ {};
    std::optional<AdvancedFlowFilterDocument> saved_baseline_ {};
    std::optional<std::filesystem::path> source_path_ {};
};

}  // namespace pfl::session_detail
