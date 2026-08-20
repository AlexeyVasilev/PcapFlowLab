#include "app/session/AdvancedFlowFilterDocumentState.h"

#include <cassert>

namespace pfl::session_detail {

const AdvancedFlowFilterDocument& AdvancedFlowFilterDocumentState::applied_document() const noexcept {
    assert_invariant();
    return applied_document_;
}

const AdvancedFlowFilterDocument* AdvancedFlowFilterDocumentState::draft_document() const noexcept {
    assert_invariant();
    return draft_document_.has_value() ? &*draft_document_ : nullptr;
}

AdvancedFlowFilterDocument* AdvancedFlowFilterDocumentState::draft_document() noexcept {
    assert_invariant();
    return draft_document_.has_value() ? &*draft_document_ : nullptr;
}

const AdvancedFlowFilterDocument& AdvancedFlowFilterDocumentState::current_user_visible_document() const noexcept {
    assert_invariant();
    return draft_document_.has_value() ? *draft_document_ : applied_document_;
}

const AdvancedFlowFilterDocument* AdvancedFlowFilterDocumentState::saved_baseline() const noexcept {
    assert_invariant();
    return saved_baseline_.has_value() ? &*saved_baseline_ : nullptr;
}

const std::filesystem::path* AdvancedFlowFilterDocumentState::source_path() const noexcept {
    assert_invariant();
    return source_path_.has_value() ? &*source_path_ : nullptr;
}

bool AdvancedFlowFilterDocumentState::is_editing() const noexcept {
    assert_invariant();
    return draft_document_.has_value();
}

bool AdvancedFlowFilterDocumentState::is_file_backed() const noexcept {
    assert_invariant();
    return source_path_.has_value();
}

bool AdvancedFlowFilterDocumentState::has_unsaved_changes() const noexcept {
    assert_invariant();
    if (!saved_baseline_.has_value()) {
        return false;
    }
    return current_user_visible_document() != *saved_baseline_;
}

bool AdvancedFlowFilterDocumentState::has_unsaved_configuration() const noexcept {
    assert_invariant();
    if (saved_baseline_.has_value()) {
        return current_user_visible_document() != *saved_baseline_;
    }
    return !is_default_advanced_flow_filter_document(current_user_visible_document());
}

bool AdvancedFlowFilterDocumentState::can_clear_unsaved_changes() const noexcept {
    assert_invariant();
    return saved_baseline_.has_value() && current_user_visible_document() != *saved_baseline_;
}

bool AdvancedFlowFilterDocumentState::would_lose_unsaved_configuration() const noexcept {
    return has_unsaved_configuration();
}

std::size_t AdvancedFlowFilterDocumentState::configured_rule_count() const noexcept {
    return count_configured_advanced_flow_filter_atomic_rules(current_user_visible_document());
}

std::size_t AdvancedFlowFilterDocumentState::active_rule_count() const {
    return count_active_advanced_flow_filter_atomic_rules(current_user_visible_document());
}

void AdvancedFlowFilterDocumentState::begin_edit() {
    assert_invariant();
    if (!draft_document_.has_value()) {
        draft_document_ = applied_document_;
    }
    assert_invariant();
}

void AdvancedFlowFilterDocumentState::cancel_edit() noexcept {
    assert_invariant();
    draft_document_.reset();
    assert_invariant();
}

bool AdvancedFlowFilterDocumentState::apply_draft() {
    assert_invariant();
    if (!draft_document_.has_value()) {
        return false;
    }

    applied_document_ = *draft_document_;
    draft_document_.reset();
    assert_invariant();
    return true;
}

bool AdvancedFlowFilterDocumentState::revert_to_saved_baseline() {
    assert_invariant();
    if (!saved_baseline_.has_value()) {
        return false;
    }

    applied_document_ = *saved_baseline_;
    if (draft_document_.has_value()) {
        *draft_document_ = *saved_baseline_;
    }
    assert_invariant();
    return true;
}

void AdvancedFlowFilterDocumentState::accept_opened_document(
    const AdvancedFlowFilterDocument& document,
    const std::filesystem::path& path
) {
    accept_file_backed_document(document, path);
}

void AdvancedFlowFilterDocumentState::accept_saved_document(
    const AdvancedFlowFilterDocument& document,
    const std::filesystem::path& path
) {
    accept_file_backed_document(document, path);
}

void AdvancedFlowFilterDocumentState::clear_all() {
    assert_invariant();
    applied_document_ = {};
    saved_baseline_.reset();
    source_path_.reset();
    if (draft_document_.has_value()) {
        *draft_document_ = {};
    }
    assert_invariant();
}

void AdvancedFlowFilterDocumentState::assert_invariant() const noexcept {
    assert(source_path_.has_value() == saved_baseline_.has_value());
}

void AdvancedFlowFilterDocumentState::accept_file_backed_document(
    const AdvancedFlowFilterDocument& document,
    const std::filesystem::path& path
) {
    assert_invariant();
    applied_document_ = document;
    saved_baseline_ = document;
    source_path_ = path;
    if (draft_document_.has_value()) {
        *draft_document_ = document;
    }
    assert_invariant();
}

}  // namespace pfl::session_detail
