# UI Improvement Backlog

## 1. Purpose

This backlog exists to guide the next phase of UI work after the recent correctness and selected-flow stabilization work.

- Move from pure behavior fixes toward better everyday usability and polish.
- Improve information density without making the UI cramped or noisy.
- Make the application easier to scan, easier to operate, and more modern-looking while staying tool-oriented.
- Prefer small, low-risk incremental improvements over disruptive redesign.

## 2. Principles

Future UI work should follow these principles.

- Compact, not cramped.
- Informative, not noisy.
- Modern, but still a professional analysis tool.
- Correctness and honesty first.
- Important information should dominate secondary metadata.
- Frequent workflows should require fewer clicks and less scanning.
- Visual modernization must not reduce information density through decorative spacing or oversized control styling.
- Conservative improvements are preferable to broad visual resets.

## 3. Current Strengths

The current UI already has several strong foundations.

- Selected-flow packet, stream, and details workflow is much clearer than before.
- Stream items are more compact and show source ownership.
- Protocol details for TLS, HTTP, and QUIC are materially more useful.
- The open/status area is clearer about active session versus background loading.
- Statistics formatting, menu structure, settings dialog, and primary open action are in a better place than earlier iterations.

## 4. Priority Buckets

### 4.1 High-Priority Usability And Density Wins

**1. Denser packet and stream pane layout**  
Problem: Dense workflows still lose space to padding, large gaps, and low-value separators.  
Proposed improvement: Tighten vertical spacing in packet list, stream list, and details panes where readability is preserved.  
Expected benefit: More useful rows and details fit on screen without changing logic.  
Risk / caution: Avoid making selection targets too small or collapsing hierarchy.  
Priority: High

**2. Better truncation with full-value access**  
Problem: Long paths, hostnames, SNI values, packet lists, and protocol lists can either overflow or become hard to inspect.  
Proposed improvement: Standardize ellipsis behavior and pair it with reliable tooltip or copy access for truncated fields.  
Expected benefit: Cleaner dense layouts without losing access to full values.  
Risk / caution: Truncation must stay predictable and must not hide critical distinctions.  
Priority: High

**3. Stronger hierarchy in details text blocks**  
Problem: Packet and stream protocol details can still read like large flat blocks, especially for TLS and QUIC.  
Proposed improvement: Continue formatting details into short sections, cleaner field ordering, and more readable long lists.  
Expected benefit: Faster scanning of protocol details and less operator fatigue.  
Risk / caution: Keep output plain-text friendly and avoid introducing implied semantics.  
Priority: High

**4. Better visibility of packet truth vs stream truth**  
Problem: Users can still confuse packet details with semantic stream-item interpretation.  
Proposed improvement: Make wording, section labels, and helper text slightly more explicit about whether a pane reflects packet bytes or stream semantics.  
Expected benefit: Fewer interpretation mistakes during analysis.  
Risk / caution: The wording must stay concise and not add explanatory clutter everywhere.  
Priority: High

**5. Smarter `Load more` and partial-analysis messaging**  
Problem: Partial selected-flow analysis is correct, but the UI can still undersell what is partial, bounded, or not yet materialized.  
Proposed improvement: Improve the visibility and wording of bounded stream state, including packet-window limits and what additional loading may change.  
Expected benefit: Better trust and fewer “is this incomplete or just empty?” moments.  
Risk / caution: Do not turn bounded-state messaging into warning noise.  
Priority: High

### 4.2 Medium-Priority Workflow And Consistency Improvements

**6. Faster copy and reference actions in analyst workflows**  
Problem: Analysts often need to copy packet references, stream/source packet references, Wireshark helper filters, protocol values, and detail snippets quickly during repeated investigation work.  
Proposed improvement: Add more direct copy affordances for common selected-flow values and details fields, especially where the copied value is used immediately in Wireshark, notes, tickets, or cross-checking.  
Expected benefit: Less manual selection and faster handoff to Wireshark, notes, or tickets.  
Risk / caution: Avoid adding copy buttons everywhere; focus on repeated high-value actions.  
Priority: Medium

**7. Top workspace density and context clarity**  
Problem: The top workspace area carries active session info, opening status, filter controls, and helper values, but it can still be denser and easier to scan.  
Proposed improvement: Tighten and clarify the header/top-workspace area so active session, opening state, filter area, and Wireshark helper visibility are easier to understand without wasting vertical space.  
Expected benefit: Faster orientation and less scanning at the start of every workflow.  
Risk / caution: Do not hide important state such as missing source capture or opening progress.  
Priority: Medium

**8. Better marker visibility without selection-like noise**  
Problem: Special packet conditions such as retransmission are useful, but markers can still be easy to miss in dense views.  
Proposed improvement: Improve marker presentation using compact badges, clearer alignment, or lighter status emphasis patterns.  
Expected benefit: Important packet conditions stand out faster during triage.  
Risk / caution: Marker styling must not make rows look permanently selected or overloaded.  
Priority: Medium

**9. More consistent naming across panes and menus**  
Problem: The app is better than before, but some labels, tab names, and action wording still vary more than ideal.  
Proposed improvement: Audit and normalize recurring terms such as payload, source packets, selected flow, opening state, and protocol labels.  
Expected benefit: Lower cognitive overhead and fewer “same concept, different wording” moments.  
Risk / caution: Do not rename stable protocol semantics casually.  
Priority: Medium

**10. Stronger empty states and unavailable states**  
Problem: Empty or unavailable panes can still feel visually similar to “nothing useful here” rather than “data unavailable for a specific reason.”  
Proposed improvement: Improve wording for empty, unavailable, partial, and source-capture-missing states.  
Expected benefit: Better user trust and clearer next action when data cannot be shown.  
Risk / caution: Keep these states compact; do not replace real content with oversized banners.  
Priority: Medium

**11. Selection continuity across related views**  
Problem: Switching flows, packets, stream items, and tabs can still create small context-loss moments.  
Proposed improvement: Review and tighten selection continuity rules so related views update predictably and keep the active context obvious.  
Expected benefit: Smoother workflow and fewer accidental context resets.  
Risk / caution: Avoid hidden persistence that makes state feel sticky in surprising ways.  
Priority: Medium

**12. More compact ownership presentation for large reassembled items**  
Problem: Source ownership is valuable, but long packet lists can become noisy in dense views.  
Proposed improvement: Keep compact shortened ownership in list views while ensuring fuller ownership stays easy to inspect in details.  
Expected benefit: Better balance between density and trustworthiness.  
Risk / caution: Never let shortened ownership imply fewer contributing packets than actually exist.  
Priority: Medium

**13. Keyboard-oriented analyst workflow improvements**  
Problem: Repeated analyst workflows still lean heavily on pointer movement for filtering, switching context, and navigating between related panes.  
Proposed improvement: Improve shortcut-friendly focus movement, faster filter/search focus, and smoother keyboard navigation across packet, stream, and details contexts.  
Expected benefit: Faster repeated analysis work, especially in dense inspection sessions.  
Risk / caution: Keyboard behavior must remain predictable and must not break existing text-entry expectations.  
Priority: Medium

### 4.3 Lower-Priority Visual Modernization And Polish

**14. Unified control and pane styling pass**  
Problem: The app still shows some default-Qt visual inconsistency across panes, buttons, inputs, and cards.  
Proposed improvement: Normalize spacing, borders, corner radius, divider style, and neutral background treatment across the main workspace.  
Expected benefit: A more cohesive and modern-looking tool without changing workflows.  
Risk / caution: Keep styling understated and professional.  
Priority: Low

**15. Cleaner typography hierarchy**  
Problem: Headers, metadata, helper text, and dense table content could use more consistent weight and contrast rules.  
Proposed improvement: Refine typography hierarchy so primary labels dominate, metadata is lighter, and dense values remain readable.  
Expected benefit: Less visual noise and faster scanning in high-information surfaces.  
Risk / caution: Do not sacrifice legibility for visual subtlety.  
Priority: Low

**16. Modernized status, badge, and tab appearance**  
Problem: Status indicators, tabs, and small metadata elements still have room to look more polished and less raw.  
Proposed improvement: Use calmer status pills, cleaner tab emphasis, and more consistent micro-components for secondary state.  
Expected benefit: A more contemporary tool feel without reducing density.  
Risk / caution: Badges and tabs must stay functional and not become decorative.  
Priority: Low

**17. Better visual treatment of analysis-tool-specific metadata**  
Problem: Ownership, direction, partial-state, and protocol-specific hints are important but not always visually prioritized well.  
Proposed improvement: Refine compact metadata presentation patterns that fit packet-analysis work, especially in stream rows and details summaries.  
Expected benefit: More trustworthy dense views tailored to analyst workflows rather than generic app styling.  
Risk / caution: Do not add decorative chrome that competes with protocol content.  
Priority: Low

## 5. Suggested Next UI Steps

1. Do one compact density pass first, focused on spacing, truncation, tooltips, and top-workspace/header clarity.
2. Do one wording and state-clarity pass next, focused on packet truth, stream truth, bounded analysis, and unavailable states.
3. Do one workflow pass after that, focused on copy/reference actions, keyboard efficiency, and selection continuity.
4. Do one restrained visual polish pass last, focused on control consistency, typography, and status/badge styling.
5. Reassess after those passes before proposing any broader layout changes.
