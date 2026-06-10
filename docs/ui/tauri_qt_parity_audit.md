# Tauri vs Qt UI Parity Audit

Date: 2026-06-06

Note: the Tauri shell has since aligned top-level tab order with Qt and now supports runtime-only adjustable splitters for the Flows and Analysis workspaces. The remaining gaps below are therefore mostly presentation depth and workflow polish rather than basic workspace structure.

## Purpose

This document is a documentation-only audit of current UI parity between the primary Qt desktop UI and the merged experimental Tauri UI.

Qt remains the reference desktop UI. Tauri now covers most primary workflows, but several presentation, workflow, and large-flow responsiveness gaps still remain.

## Scope And Method

This audit is based on static inspection of:

- Qt controller and QML:
  - `src/ui/app/MainController.cpp`
  - `src/ui/qml/Main.qml`
  - `src/ui/qml/components/*.qml`
- Tauri docs and plain web shell:
  - `experimental/tauri-ui-spike/README.md`
  - `experimental/tauri-ui-spike/web/index.html`
  - `experimental/tauri-ui-spike/web/main.js`
  - `experimental/tauri-ui-spike/web/styles.css`

## Non-Goals

- No code changes
- No DTO changes
- No build changes
- No performance implementation
- No CSP/security hardening implementation

## Parity Matrix

| Area | Qt behavior | Current Tauri behavior | Gap | Priority | Suggested follow-up |
| --- | --- | --- | --- | --- | --- |
| Menus | `File / Flow / View` menus are fully wired in QML and drive controller actions. | Same menu shell is present and wired in the plain HTML/JS shell. | Low remaining parity gap. Main difference is presentation polish, not capability. | Low | Keep labels and enable/disable behavior aligned as small polish work only. |
| Open capture workflow | Native open dialog, Fast/Deep open modes, explicit open progress, session-apply overlay, and controller-owned status/error text. | Native file dialog, Fast/Deep selector, Qt-like active-session display, real shared-backend open progress/cancel, and compact status/source-warning messaging. | Main capability gap is now mostly presentation polish, not workflow shape. | Low | Keep wording and spacing aligned with Qt as small shell polish only. |
| Open index workflow | Native open dialog and index-backed session shell with expected-source state. | Native open dialog, index-backed active-session display, and shared source-availability messaging. | Workflow exists; remaining gap is mostly index-shell wording/presentation polish. | Medium | Small parity pass on index shell text, expected-path messaging, and unavailable-source presentation. |
| Save index workflow | `File -> Save Index` available only when controller rules allow it; uses native save dialog and `.idx`. | Same workflow exists in Tauri via menu and native save dialog. | Capability is present; main differences are status messaging and shell polish only. | Low | Keep current implementation; revisit only if Qt save-index messaging changes. |
| Attach source capture | Qt surfaces explicit unavailable-source state, expected source path, `Locate Source Capture`, and preserves session if the chosen file mismatches. | Tauri surfaces grouped source-warning banner, expected source path, and `Locate Source...` attach workflow using the same validation path. | Capability exists; wording and button naming are slightly different, and Tauri presentation is more compact than Qt. | Medium | Align banner/button text and expected-path presentation with Qt copy. |
| Export current flow | Menu action is enabled only when source bytes are available and a selected flow exists; native save dialog with `.pcap`. | Same narrow workflow is implemented and gated by source availability plus selected flow state. | Low gap. Mostly copy/polish. | Low | No backend change; keep parity by matching success/error text where practical. |
| Export selected flows | Qt uses checked-flow selection, native save dialog, and shared session export path. | Same workflow exists and uses checked-flow selection keyed by `flow_index`. | Low gap. | Low | Maintain current behavior; only small wording polish if needed. |
| Export unselected flows | Qt exports the inverse of checked flows over the loaded set when source bytes are available. | Same inverse-of-checked-flow export is implemented. | Low gap. | Low | Keep as-is. |
| Smart Export | Qt has a richer dialog plus explicit progress/cancel UI during long-running export. | Tauri mirrors scope/base/output options and folder mode, but uses a simpler custom dialog and lighter status reporting. | Missing richer Qt progress/cancel UX parity and some dialog-level copy/layout fidelity. | Medium | Small UI polish pass: align labels/help text first, then consider richer progress/cancel parity. |
| Settings | Qt `View -> Settings` is implemented and currently exposes the shared runtime-safe settings slice directly through QML/controller properties. | Tauri `View -> Settings` supports the same currently wired settings slice. | Core working slice matches, but persistence remains deferred and the dialog is still lighter-weight. | Medium | Keep settings scope stable; defer persistence until broader settings strategy is agreed. |
| Flows table | Qt uses a dense list-based table with checked-flow boxes, sort buttons, filter, Wireshark filter row, and `Send flow to Analysis`. | Tauri has filtering, sorting, checked-flow state, Wireshark filter row toggle, and frontend virtualization/windowing. | Tauri is closer functionally, but row styling, per-column density, and exact workflow affordances still differ. | Medium | UI polish pass focused on row density, spacing, and top-of-flows controls. |
| Checked-flow selection and selection status | Qt shows checked-flow state in-table and a bottom selection status bar when any flows are checked. | Tauri keeps checked-flow state across sorting/filtering and shows a compact checked-flow status bar. | Small presentation gap only. | Low | Keep behavior; only match wording/styling if needed. |
| Packet list | Qt packet list is bounded, supports `Load more`, shows direction chips, truncation/fragment cues, and a dedicated marker column only when needed. | Tauri packet list is now bounded with append-only `Load More`, but does not yet mirror the same visual richness or marker treatment. | The main remaining gap is presentation density and lower-workspace polish rather than paging semantics. | Medium | Keep the bounded `Load More` model and continue with compact row styling, marker treatment, and lower-workspace visual polish. |
| Packet details | Qt packet/stream details pane is richer: warnings block extraction, dynamic header for stream items, better text panes, and tighter tab behavior. | Tauri supports `Summary / Raw / Payload / Protocol`, bounded previews, checksum setting, and metadata summary. | Tauri is functionally useful but still visually and structurally simpler than Qt. | High | Packet details display polish pass to align warning sections, section grouping, and stream-item detail treatment. |
| Stream view | Qt stream view is selected-flow-only, bounded, lazy, and has better bubble/chat-like presentation plus constricted badges and `Load more`. | Tauri stream view is selected-flow-only, bounded, lazy, selectable, and shows basic details. | Tauri lacks the richer bubble presentation and some stream-item context that Qt already exposes. | High | Stream UI parity pass after packet-details polish; keep backend loading semantics unchanged. |
| Stream item details | Qt has a dedicated stream-item detail presentation through the packet-details pane, with contextual headers and source-packet summaries. | Tauri shows basic selected stream-item details and source packet lists. | Tauri details are thinner and less contextual. | High | Fold stream-item detail polish into the packet-details parity pass. |
| Statistics overview | Qt uses summary cards plus denser percentage-heavy protocol/family tables and conditional top-talker sections. | Tauri provides overview cards, transport/family/protocol-hint summaries, QUIC/TLS blocks, and top endpoints/ports. | Capability is mostly present, but percentage formatting and some conditional presentation are still simpler. | Medium | Statistics polish pass focused on percentages, compactness, and drill-down affordances. |
| Statistics drill-down | Qt drill-down reuses flows filtering and top talker activation through controller helpers. | Tauri drill-down switches back to `Flows` and applies the shared filter text. | Useful but still coarse; no direct row/packet/detail navigation. | Medium | Consider direct row focus or preserved highlight after the filter pass, but keep backend unchanged. |
| Analysis flow list | Qt Analysis has its own left flow list with compact dense row layout and shared selected-flow behavior. | Tauri now has its own left Analysis flow list built from loaded Flow DTOs and virtualized on the frontend. | Small remaining layout/density differences only. | Low | Maintain current behavior; polish spacing/truncation only if needed. |
| Analysis details | Qt has the broader selected-flow analysis workspace including summary, protocol panel, derived metrics, burst/idle, histograms, sequence preview, and rate graph. | Tauri now covers most read-only sections: summary, protocol panel, totals, direction split, derived metrics, timing/size, burst/idle, TCP controls, histograms, sequence preview, and CSV export. | Biggest missing piece is the Qt rate graph and fuller presentation polish. | Medium | Next analysis parity step should be UI polish first, then rate-graph parity if still desired. |
| Analysis export | Qt exposes sequence export from the analysis workspace. | Tauri supports selected-flow sequence CSV export with native save dialog. | Low gap. | Low | Keep current workflow; document any CSV shape differences if they appear later. |
| Status and error messaging | Qt has more controller-owned inline labels, warning bars, smart-export progress text, and session/open overlays. | Tauri has badges, inline status text, source warning banner, and non-fatal messages, but with less nuance. | Tauri messaging is good enough operationally but less mature and less consistent. | Medium | Short polish pass across top-shell, export, and unavailable-source messaging. |
| Empty/loading/error states | Qt generally has more deliberate placeholders for no capture, no selected flow, unavailable source, loading stream, loading analysis, and apply-session overlay. | Tauri covers all major empty/loading/error states, but some states are simpler and less visually anchored. | Coverage exists; parity gap is mostly presentation depth and consistency. | Medium | Cross-cutting polish pass for empty/loading/error cards and compact placeholder text. |
| Large flow table responsiveness | Qt still keeps full model data and is not immune to large-capture cost. | Tauri adds frontend virtualization/windowing for main Flows and Analysis flow lists. | Tauri is ahead in this one frontend area, but still holds full Flow DTO arrays in JS. | Medium | Post-merge optimization work should focus on DTO slicing or backend paging only if needed. |
| Selected-flow packet/stream latency on very large flows | Qt and shared backend still pay noticeable cost on very large flows before Stream/details become useful. | Tauri is bounded and lazy, but still shares the same backend/session latency characteristics for very large flows. | Shared optimization gap, not a Tauri-only parity issue. | High | Investigate shared backend packet-byte read and selected-flow packet/stream loading path before adding more UI complexity. |

## Main Gaps

### 1. Packet and stream presentation still trail Qt

The biggest visible parity gap is no longer feature coverage. It is the lower workspace polish:

- packet list row styling and navigation feel lighter than Qt
- packet details are functionally complete enough but still less structured
- stream and stream-item details remain simpler than the Qt workspace

### 2. Smart Export UX is functional but not fully Qt-grade

Tauri now has the workflow, but Qt still has the stronger long-running export UX:

- richer progress feedback
- explicit cancel path presentation
- more mature dialog copy/layout

### 3. Statistics and top-shell messaging need compactness polish

Tauri already covers the read-side statistics surface, but Qt remains denser and more presentation-complete in:

- percentage formatting
- conditional sections
- source/index warning copy
- open/apply/progress messaging

### 4. Large selected-flow packet/stream latency remains a shared issue

This is not just a Tauri parity problem. Static inspection still points to a shared backend/session cost area for:

- very large selected-flow packet loading
- very large selected-flow stream reconstruction
- packet-byte reads when the user only needs a small initial slice

## Recommended Next UI Parity Passes

1. Packet list and packet-details polish
2. Stream and stream-item-details presentation polish
3. Top-shell plus source/index warning/message polish
4. Statistics compactness and percentage-format polish
5. Smart Export progress/cancel UX polish
6. Analysis rate-graph parity only after the lower-workspace and messaging surfaces feel stable

## Merge-Ready Position

Tauri is no longer a placeholder shell. It now covers most primary workflows:

- open capture/index
- save index
- attach source
- flow exports
- settings
- flows/filter/sort/checked selection
- packet details
- stream
- statistics
- selected-flow analysis

The remaining gaps are mostly:

- UI density/presentation fidelity versus Qt
- long-running workflow polish
- large-flow responsiveness in selected-flow packet/stream paths

## Open Questions For Manual Review

1. Whether the current bounded Tauri packet list needs further row-density polish after switching to Qt-like `Load more` semantics.
2. Whether direct stream-item-to-packet navigation should be considered a parity blocker or remain a later polish item.
3. Whether the Qt rate graph still needs parity in the near term, or whether packet/stream/details polish is clearly the better next step.
4. Whether current source/index top-shell wording should be standardized verbatim across Qt and Tauri.
5. Whether full settings persistence is intended to stay deferred for both product direction and merge scope.
