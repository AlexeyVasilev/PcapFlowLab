#include <filesystem>

#include "TestSupport.h"
#include "app/session/AdvancedFlowFilterDocumentState.h"

namespace pfl::tests {

namespace {

using session_detail::AdvancedFlowFilterDirectionality;
using session_detail::AdvancedFlowFilterDocument;
using session_detail::AdvancedFlowFilterDocumentState;

AdvancedFlowFilterDocument make_tcp_document() {
    AdvancedFlowFilterDocument document {};
    document.configured_spec.flow_protocol.include.push_back(ProtocolId::tcp);
    return document;
}

AdvancedFlowFilterDocument make_udp_document() {
    AdvancedFlowFilterDocument document {};
    document.configured_spec.flow_protocol.include.push_back(ProtocolId::udp);
    return document;
}

AdvancedFlowFilterDocument make_enabled_state_only_document() {
    AdvancedFlowFilterDocument document {};
    document.section_states.ports = false;
    return document;
}

AdvancedFlowFilterDocument make_bidirectional_document() {
    AdvancedFlowFilterDocument document {};
    document.configured_spec.directionality.include.push_back(AdvancedFlowFilterDirectionality::bidirectional);
    return document;
}

void expect_source_baseline_invariant(const AdvancedFlowFilterDocumentState& state) {
    PFL_EXPECT((state.source_path() == nullptr) == (state.saved_baseline() == nullptr));
}

void run_state_lifecycle_tests() {
    ScopedTestContext context {"advanced_flow_filter/document_state"};

    {
        AdvancedFlowFilterDocumentState state {};
        PFL_EXPECT(state.applied_document() == AdvancedFlowFilterDocument {});
        PFL_EXPECT(state.current_user_visible_document() == AdvancedFlowFilterDocument {});
        PFL_EXPECT(state.draft_document() == nullptr);
        PFL_EXPECT(state.saved_baseline() == nullptr);
        PFL_EXPECT(state.source_path() == nullptr);
        PFL_EXPECT(state.is_editing() == false);
        PFL_EXPECT(state.is_file_backed() == false);
        PFL_EXPECT(state.configured_rule_count() == 0U);
        PFL_EXPECT(state.active_rule_count() == 0U);
        PFL_EXPECT(state.has_unsaved_changes() == false);
        PFL_EXPECT(state.has_unsaved_configuration() == false);
        PFL_EXPECT(state.can_clear_unsaved_changes() == false);
        PFL_EXPECT(state.would_lose_unsaved_configuration() == false);
        expect_source_baseline_invariant(state);
    }

    {
        AdvancedFlowFilterDocumentState state {};
        state.begin_edit();
        PFL_REQUIRE(state.draft_document() != nullptr);
        PFL_EXPECT(*state.draft_document() == state.applied_document());

        state.draft_document()->configured_spec.flow_protocol.include.push_back(ProtocolId::tcp);
        const auto draft_before_second_begin = *state.draft_document();
        state.begin_edit();
        PFL_REQUIRE(state.draft_document() != nullptr);
        PFL_EXPECT(*state.draft_document() == draft_before_second_begin);
        PFL_EXPECT(state.applied_document() == AdvancedFlowFilterDocument {});
        expect_source_baseline_invariant(state);
    }

    {
        AdvancedFlowFilterDocumentState state {};
        state.begin_edit();
        PFL_REQUIRE(state.draft_document() != nullptr);
        state.draft_document()->configured_spec.flow_protocol.include.push_back(ProtocolId::tcp);
        PFL_EXPECT(state.applied_document() == AdvancedFlowFilterDocument {});
        PFL_EXPECT(state.current_user_visible_document() == *state.draft_document());
        expect_source_baseline_invariant(state);
    }

    {
        AdvancedFlowFilterDocumentState state {};
        state.begin_edit();
        PFL_REQUIRE(state.draft_document() != nullptr);
        state.draft_document()->configured_spec.flow_protocol.include.push_back(ProtocolId::tcp);
        state.cancel_edit();
        PFL_EXPECT(state.is_editing() == false);
        PFL_EXPECT(state.draft_document() == nullptr);
        PFL_EXPECT(state.applied_document() == AdvancedFlowFilterDocument {});
        expect_source_baseline_invariant(state);
    }

    {
        AdvancedFlowFilterDocumentState state {};
        state.begin_edit();
        PFL_REQUIRE(state.draft_document() != nullptr);
        *state.draft_document() = make_tcp_document();
        PFL_EXPECT(state.apply_draft() == true);
        PFL_EXPECT(state.is_editing() == false);
        PFL_EXPECT(state.applied_document() == make_tcp_document());
        PFL_EXPECT(state.current_user_visible_document() == make_tcp_document());
        PFL_EXPECT(state.has_unsaved_configuration() == true);
        expect_source_baseline_invariant(state);
    }

    {
        AdvancedFlowFilterDocumentState state {};
        const auto opened_document = make_tcp_document();
        const auto opened_path = std::filesystem::path {"filters/opened.filter"};
        state.accept_opened_document(opened_document, opened_path);
        PFL_EXPECT(state.is_file_backed() == true);
        PFL_EXPECT(state.is_editing() == false);
        PFL_REQUIRE(state.saved_baseline() != nullptr);
        PFL_REQUIRE(state.source_path() != nullptr);
        PFL_EXPECT(state.applied_document() == opened_document);
        PFL_EXPECT(*state.saved_baseline() == opened_document);
        PFL_EXPECT(*state.source_path() == opened_path);
        PFL_EXPECT(state.has_unsaved_changes() == false);
        PFL_EXPECT(state.can_clear_unsaved_changes() == false);

        state.begin_edit();
        PFL_REQUIRE(state.draft_document() != nullptr);
        state.draft_document()->configured_spec.flow_protocol.include.push_back(ProtocolId::udp);
        const auto replacement_document = make_udp_document();
        const auto replacement_path = std::filesystem::path {"filters/replacement.filter"};
        state.accept_opened_document(replacement_document, replacement_path);
        PFL_EXPECT(state.is_editing() == true);
        PFL_REQUIRE(state.draft_document() != nullptr);
        PFL_REQUIRE(state.saved_baseline() != nullptr);
        PFL_REQUIRE(state.source_path() != nullptr);
        PFL_EXPECT(state.applied_document() == replacement_document);
        PFL_EXPECT(*state.draft_document() == replacement_document);
        PFL_EXPECT(*state.saved_baseline() == replacement_document);
        PFL_EXPECT(*state.source_path() == replacement_path);
        PFL_EXPECT(state.has_unsaved_changes() == false);
        expect_source_baseline_invariant(state);
    }

    {
        AdvancedFlowFilterDocumentState state {};
        const auto baseline_document = make_tcp_document();
        state.accept_opened_document(baseline_document, std::filesystem::path {"filters/baseline.filter"});
        state.begin_edit();
        PFL_REQUIRE(state.draft_document() != nullptr);
        state.draft_document()->configured_spec.flow_protocol.include.push_back(ProtocolId::udp);
        PFL_EXPECT(state.has_unsaved_changes() == true);
        PFL_EXPECT(state.has_unsaved_configuration() == true);
        PFL_EXPECT(state.can_clear_unsaved_changes() == true);
        PFL_EXPECT(state.would_lose_unsaved_configuration() == true);
        expect_source_baseline_invariant(state);
    }

    {
        AdvancedFlowFilterDocumentState state {};
        const auto baseline_document = make_tcp_document();
        const auto dirty_document = make_bidirectional_document();
        state.accept_opened_document(baseline_document, std::filesystem::path {"filters/baseline.filter"});
        state.begin_edit();
        PFL_REQUIRE(state.draft_document() != nullptr);
        *state.draft_document() = dirty_document;
        PFL_EXPECT(state.apply_draft() == true);
        PFL_EXPECT(state.is_editing() == false);
        PFL_EXPECT(state.applied_document() == dirty_document);
        PFL_REQUIRE(state.saved_baseline() != nullptr);
        PFL_EXPECT(*state.saved_baseline() == baseline_document);
        PFL_EXPECT(state.has_unsaved_changes() == true);
        PFL_EXPECT(state.can_clear_unsaved_changes() == true);
        expect_source_baseline_invariant(state);
    }

    {
        AdvancedFlowFilterDocumentState state {};
        const auto baseline_document = make_tcp_document();
        const auto dirty_document = make_bidirectional_document();
        state.accept_opened_document(baseline_document, std::filesystem::path {"filters/baseline.filter"});
        state.begin_edit();
        PFL_REQUIRE(state.draft_document() != nullptr);
        *state.draft_document() = dirty_document;
        PFL_EXPECT(state.apply_draft() == true);
        PFL_EXPECT(state.revert_to_saved_baseline() == true);
        PFL_EXPECT(state.applied_document() == baseline_document);
        PFL_EXPECT(state.is_editing() == false);
        PFL_EXPECT(state.has_unsaved_changes() == false);
        PFL_EXPECT(state.can_clear_unsaved_changes() == false);
        expect_source_baseline_invariant(state);
    }

    {
        AdvancedFlowFilterDocumentState state {};
        const auto baseline_document = make_tcp_document();
        const auto dirty_document = make_bidirectional_document();
        state.accept_opened_document(baseline_document, std::filesystem::path {"filters/baseline.filter"});
        state.begin_edit();
        PFL_REQUIRE(state.draft_document() != nullptr);
        *state.draft_document() = dirty_document;
        PFL_EXPECT(state.revert_to_saved_baseline() == true);
        PFL_EXPECT(state.is_editing() == true);
        PFL_REQUIRE(state.draft_document() != nullptr);
        PFL_EXPECT(state.applied_document() == baseline_document);
        PFL_EXPECT(*state.draft_document() == baseline_document);
        state.cancel_edit();
        PFL_EXPECT(state.applied_document() == baseline_document);
        PFL_EXPECT(state.has_unsaved_changes() == false);
        expect_source_baseline_invariant(state);
    }

    {
        AdvancedFlowFilterDocumentState state {};
        state.begin_edit();
        PFL_REQUIRE(state.draft_document() != nullptr);
        *state.draft_document() = make_tcp_document();
        const auto saved_document = make_bidirectional_document();
        const auto saved_path = std::filesystem::path {"filters/saved.filter"};
        state.accept_saved_document(saved_document, saved_path);
        PFL_EXPECT(state.is_file_backed() == true);
        PFL_EXPECT(state.is_editing() == true);
        PFL_REQUIRE(state.draft_document() != nullptr);
        PFL_REQUIRE(state.saved_baseline() != nullptr);
        PFL_REQUIRE(state.source_path() != nullptr);
        PFL_EXPECT(state.applied_document() == saved_document);
        PFL_EXPECT(*state.draft_document() == saved_document);
        PFL_EXPECT(*state.saved_baseline() == saved_document);
        PFL_EXPECT(*state.source_path() == saved_path);
        PFL_EXPECT(state.has_unsaved_changes() == false);
        expect_source_baseline_invariant(state);
    }

    {
        AdvancedFlowFilterDocumentState state {};
        const auto original_document = make_tcp_document();
        state.accept_saved_document(original_document, std::filesystem::path {"filters/original.filter"});
        const auto replacement_document = make_bidirectional_document();
        const auto replacement_path = std::filesystem::path {"filters/replacement.filter"};
        state.accept_saved_document(replacement_document, replacement_path);
        PFL_REQUIRE(state.source_path() != nullptr);
        PFL_REQUIRE(state.saved_baseline() != nullptr);
        PFL_EXPECT(*state.source_path() == replacement_path);
        PFL_EXPECT(*state.saved_baseline() == replacement_document);
        PFL_EXPECT(state.applied_document() == replacement_document);
        expect_source_baseline_invariant(state);
    }

    {
        AdvancedFlowFilterDocumentState state {};
        PFL_EXPECT(state.has_unsaved_configuration() == false);
        state.begin_edit();
        PFL_REQUIRE(state.draft_document() != nullptr);
        *state.draft_document() = make_tcp_document();
        PFL_EXPECT(state.has_unsaved_configuration() == true);
        PFL_EXPECT(state.configured_rule_count() == 1U);
        PFL_EXPECT(state.active_rule_count() == 1U);

        AdvancedFlowFilterDocumentState enabled_state_only {};
        enabled_state_only.begin_edit();
        PFL_REQUIRE(enabled_state_only.draft_document() != nullptr);
        *enabled_state_only.draft_document() = make_enabled_state_only_document();
        PFL_EXPECT(enabled_state_only.has_unsaved_configuration() == true);
        PFL_EXPECT(enabled_state_only.has_unsaved_changes() == false);
        PFL_EXPECT(enabled_state_only.configured_rule_count() == 0U);
        PFL_EXPECT(enabled_state_only.active_rule_count() == 0U);
        expect_source_baseline_invariant(enabled_state_only);
    }

    {
        AdvancedFlowFilterDocumentState state {};
        state.accept_opened_document(make_tcp_document(), std::filesystem::path {"filters/baseline.filter"});
        state.clear_all();
        PFL_EXPECT(state.applied_document() == AdvancedFlowFilterDocument {});
        PFL_EXPECT(state.current_user_visible_document() == AdvancedFlowFilterDocument {});
        PFL_EXPECT(state.saved_baseline() == nullptr);
        PFL_EXPECT(state.source_path() == nullptr);
        PFL_EXPECT(state.is_file_backed() == false);
        PFL_EXPECT(state.has_unsaved_configuration() == false);
        PFL_EXPECT(state.configured_rule_count() == 0U);
        PFL_EXPECT(state.active_rule_count() == 0U);
        expect_source_baseline_invariant(state);
    }

    {
        AdvancedFlowFilterDocumentState state {};
        state.accept_opened_document(make_tcp_document(), std::filesystem::path {"filters/baseline.filter"});
        state.begin_edit();
        PFL_REQUIRE(state.draft_document() != nullptr);
        *state.draft_document() = make_bidirectional_document();
        PFL_EXPECT(state.apply_draft() == true);
        state.clear_all();
        PFL_EXPECT(state.applied_document() == AdvancedFlowFilterDocument {});
        PFL_EXPECT(state.has_unsaved_configuration() == false);
        PFL_EXPECT(state.is_file_backed() == false);
        expect_source_baseline_invariant(state);
    }

    {
        AdvancedFlowFilterDocumentState state {};
        state.accept_opened_document(make_tcp_document(), std::filesystem::path {"filters/baseline.filter"});
        state.begin_edit();
        PFL_REQUIRE(state.draft_document() != nullptr);
        *state.draft_document() = make_bidirectional_document();
        state.clear_all();
        PFL_EXPECT(state.is_editing() == true);
        PFL_REQUIRE(state.draft_document() != nullptr);
        PFL_EXPECT(state.applied_document() == AdvancedFlowFilterDocument {});
        PFL_EXPECT(*state.draft_document() == AdvancedFlowFilterDocument {});
        PFL_EXPECT(state.saved_baseline() == nullptr);
        PFL_EXPECT(state.source_path() == nullptr);
        state.cancel_edit();
        PFL_EXPECT(state.applied_document() == AdvancedFlowFilterDocument {});
        PFL_EXPECT(state.current_user_visible_document() == AdvancedFlowFilterDocument {});
        expect_source_baseline_invariant(state);
    }

    {
        AdvancedFlowFilterDocumentState state {};
        PFL_EXPECT(state.current_user_visible_document() == state.applied_document());
        state.begin_edit();
        PFL_REQUIRE(state.draft_document() != nullptr);
        *state.draft_document() = make_tcp_document();
        PFL_EXPECT(state.current_user_visible_document() == *state.draft_document());
        expect_source_baseline_invariant(state);
    }

    {
        AdvancedFlowFilterDocumentState state {};
        PFL_EXPECT(state.apply_draft() == false);
        PFL_EXPECT(state.revert_to_saved_baseline() == false);
        expect_source_baseline_invariant(state);
    }
}

}  // namespace

void run_advanced_flow_filter_document_state_tests() {
    run_state_lifecycle_tests();
}

}  // namespace pfl::tests
