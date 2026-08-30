# Frontend DTO Mapping Audit

## Status and role

This document is an implementation audit of how the shared presentation contract
maps onto the current frontend/session/Qt/Tauri code.

It is an engineering reference. It may contain point-in-time implementation
notes, mismatches, and follow-up observations.

[presentation_contract.md](presentation_contract.md) remains the canonical
current product/presentation contract.

This document does not define product behavior on its own.

## Purpose

The goal of this audit is to show:

- which semantics are already shared cleanly;
- which data currently comes from `FrontendSessionAdapter` and bridge-friendly
  DTOs;
- which parts Qt still accesses directly through `CaptureSession` /
  `MainController`;
- which frontend-local interaction layers remain intentionally frontend-owned;
- which mismatches are real implementation drift versus simply different UI
  layout choices.

## Current architecture summary

### Shared backend/session ownership

The shared C++ backend/session/presentation layers currently own:

- flow/session semantics;
- Protocol Path presentation mapping;
- structured Statistics DTOs;
- Supported Protocol Catalog exposure;
- Packet Summary structure;
- Packet Bytes descriptors and selected-view content materialization;
- Stream Item Data ownership/materialization;
- selected-flow analysis DTO shaping where currently exposed;
- source-availability facts and attach-source behavior;
- save-index and flow-export API boundaries.

### FrontendSessionAdapter scope

`FrontendSessionAdapter` is a useful shared application-facing read/write
boundary, especially for:

- capture/index opening;
- source availability;
- save index;
- attach source capture;
- supported protocol catalog;
- flow queries and flow exports;
- packet details;
- stream details;
- statistics DTOs;
- selected-flow analysis DTOs.

### Qt path

Qt does not route everything through `FrontendSessionAdapter`.

`MainController` still uses `CaptureSession` and session-level presentation
helpers directly for a large part of the desktop workflow, including:

- flows model ownership;
- packet/stream selection orchestration;
- local packet-details and stream-details view-model coordination;
- Qt-local analysis and statistics wiring;
- some settings/runtime state handling.

### Tauri path

Tauri is much closer to the adapter/bridge boundary:

- Rust/Tauri commands call the shared bridge;
- DTOs are marshaled through `FrontendSessionAdapterBridge`;
- `web/main.js` owns frontend-local state machines and rendering over those
  shared DTOs.

The important architectural conclusion is unchanged:

- Qt, Tauri, and CLI do not implement independent packet parsing or grouping
  architectures;
- they consume shared backend/session semantics through different application
  access paths.

## High-value current mappings

### Flow DTOs

Current shared flow-facing fields are strong and already useful across
frontends:

- `flow_index`
- family
- protocol text
- protocol hint + detected-protocol display text
- service hint
- endpoint A / endpoint B
- protocol path id
- fragmentation facts
- packet count
- total/original-byte count
- Wireshark display filter text

Qt still layers local model/filter/sort behavior on top of these fields.
Tauri uses bridge DTOs more directly.

### Protocol Path presentation

Current shared Protocol Path presentation is backed by shared C++ structures and
DTOs, including:

- compact path text;
- full path text;
- badge/chip rows;
- protocol-path statistics rows;
- protocol-path legend entries.

Qt and Tauri both consume that shared presentation mapping. The frontends are
not supposed to maintain independent path-label taxonomies.

### Supported Protocol Catalog

Supported protocol capability presentation is now shared cleanly:

- backend `SupportedProtocolCatalog` is authoritative;
- `FrontendSessionAdapter` exposes it;
- Qt and Tauri render the same compact catalog semantics;
- the compact table in `docs/protocols/protocol_support.md` is expected to stay
  synchronized with the same backend catalog.

### Packet Summary and Packet Bytes

Current shared packet-inspection coverage already includes:

- structured packet summary layers;
- stable packet byte-view descriptors;
- selected-view-only byte materialization;
- explicit unavailable/state/status metadata.

Qt still owns more local inspector composition and presentation details, but the
important packet semantics are already backend-driven rather than Qt-only.

### Stream item summary and Item Data

Current shared stream-item support includes:

- stream item rows with stable `stream_item_index`;
- stream item summary layers/text;
- shared `Item Data` ownership/materialization fields;
- explicit availability/state/status metadata;
- bounded selected-item semantics.

The major remaining gap is not byte ownership semantics. It is mostly frontend
presentation polish and optional navigation affordances such as stream-to-packet
jump behavior.

### Source availability and attach-source

Current shared source-availability facts are grouped meaningfully:

- has source capture;
- source capture accessible;
- opened from index;
- partial open;
- byte-backed inspection available;
- active source path;
- expected source path;
- current flow-grouping normalization facts for the loaded raw session.

Attach-source behavior and save-index behavior also have meaningful shared
adapter boundaries now.

### Statistics DTOs

Current shared statistics coverage includes:

- overview summary;
- whole-capture totals;
- capture-time DTO fields and shared UTC/duration formatting;
- capture-metrics DTO fields derived from `CapturePacketStatistics`;
- flow-characteristics DTO fields derived from `CaptureGeneralStatistics`;
- packet-direction and original-byte-direction distribution DTO rows;
- partial-open Statistics warning text;
- transport/family summary values;
- packet-size distribution DTO rows carrying both captured and original
  packet-length bucket values so Qt/Tauri can switch modes locally after one
  lazy load;
- flows-by-packet-count histogram DTO rows carrying flow counts plus captured
  and original byte aggregates for the same bucket membership;
- protocol-hint statistics;
- Protocol Path statistics;
- QUIC/TLS statistics;
- top endpoints and ports with shared flow-count, packet-count, and original-
  byte presentation values;
- top-flow rows with shared flow numbering, endpoint/protocol/detected/service
  text, compact Protocol Path text, and packet/captured/original totals.

Qt and Tauri still differ in layout and local drill-down interaction, but the
main data model is already shared.

### Analysis DTOs

Current shared selected-flow analysis DTOs already cover a substantial slice:

- endpoint summary;
- protocol/service/version text;
- timing metrics;
- traffic totals;
- directional counts;
- derived metrics;
- TCP control counts where applicable;
- burst/idle metrics;
- rate-graph points/status;
- histogram rows;
- sequence preview rows;
- sequence export API.

Stage 3A and Stage 3B extend that shared analysis DTO contract and now drive
the visible desktop Analysis controls directly:

- packet-size histogram data now carries both `original` and `captured`
  dimensions for `all`, `A->B`, and `B->A`;
- rate points now carry explicit `original_data_per_second` and
  `packets_per_second`, with Stage 3B removing the temporary
  `data_per_second` compatibility alias from the selected-flow Analysis DTO;
- analysis timing now carries raw absolute start/end timestamps plus shared
  frontend-formatted full UTC start/end text and millisecond-precision
  duration text, with Stage 3B removing the older time-of-day-only selected-
  flow presentation aliases;
- packet-size histogram data now uses the explicit
  `packet_size_histogram_dimension_rows` matrix as the shared selected-flow
  Analysis contract for `Original` and `Captured` across `All`, `A->B`, and
  `B->A`.

Qt still exposes the richer reference workspace. Tauri now consumes a meaningful
shared selected-flow analysis slice rather than a fake placeholder.

## Important current mismatches

### Qt direct session usage versus adapter usage

This is the most important architectural precision to keep explicit:

- Tauri uses the adapter/bridge path as its primary surface;
- CLI commands also consume `FrontendSessionAdapter` where appropriate;
- Qt `MainController` still uses `CaptureSession` directly in many places.

Therefore it is inaccurate to describe all frontends as using the same adapter
call path, even though they still share the same backend/session semantics.

### Settings behavior

Current main behavior uses the same high-level settings transaction model in
both desktop frontends.

- Tauri stages dialog draft state and commits it on `OK`.
- Qt also stages draft state in the dialog, initializes that draft from current
  committed values when opened, and applies the draft only on `OK`.

The shared settings DTO is real, and current dialog commit semantics are now
aligned at the frontend-contract level.

### Grouping banners for index sessions

Index-session grouping messaging must stay separate from authoritative grouping
provenance.

- grouping settings are committed through the normal settings draft/`OK` flow;
- their grouping effect still applies only to the next raw capture import or a
  reopened raw session;
- an opened index preserves the grouping stored in that index;
- current checkbox state is not authoritative historical metadata describing
  how an opened index was originally built.

### Batch-selection state

Checked-flow selection remains frontend-local state.

That is acceptable for the current product. It does not need to become a
frontend-neutral DTO merely because both Qt and Tauri support batch actions.

### Open/status shell state

Tauri has a cleaner explicit frontend-local shell state machine for some areas
such as dialog visibility and open-state transitions.

Qt spreads equivalent meaning across `MainController` properties.

This is a useful implementation note, but not a sign that Tauri owns a more
authoritative product contract.

## Current mapping status by area

### Already well shared

- flow row semantics;
- Protocol Path presentation;
- Supported Protocol Catalog;
- Packet Summary structure;
- Packet Bytes descriptors/materialization;
- Stream Item Data ownership/materialization;
- source availability;
- attach source;
- save index;
- current flow export / selected-flow export / Smart Export backend APIs;
- Statistics DTOs, including overview-backed TCP flag rows with shared percent
  text;
- selected-flow analysis DTOs.

### Shared semantics with frontend-local composition

- flow filtering and sorting;
- checked-flow batch selection;
- local shell/status rendering;
- packet inspector layout;
- stream details layout;
- statistics section layout and expansion UI;
- analysis layout and graph rendering.

### Still genuinely follow-up territory

- whether some remaining Qt-local inspector composition should move behind a
  thinner shared presentation boundary;
- whether a future frontend-neutral selected-stream-item navigation contract is
  worthwhile;
- whether any broader DTO cleanup is justified beyond accuracy/polish.

## Notes on rows that no longer describe current reality

The older audit language that implied “what should be handled first” for already
completed work is no longer the right framing.

The following areas are no longer best described as missing foundational work:

- Supported Protocol Catalog exposure;
- Packet Bytes descriptor/materialization ownership;
- Stream Item Data ownership/materialization;
- structured Statistics DTOs;
- selected-flow analysis DTO surface for Tauri;
- attach-source and save-index adapter paths;
- flow export / Smart Export shared backend APIs.

Future cleanup, where still useful, should be described as follow-up polish or
boundary refinement, not as “still missing core architecture”.

## Relationship to the canonical contract

Use this document when the question is:

- “Which current C++/Qt/Tauri path owns this field?”
- “Is this already adapter/bridge friendly?”
- “Is this shared semantics or frontend-local composition?”

Use [presentation_contract.md](presentation_contract.md) when the question is:

- “What is the canonical current product-facing UI behavior?”
- “What terminology is current?”
- “What semantics should Qt and Tauri share even when their layouts differ?”

## Non-goals

This audit does not:

- redefine the canonical product contract;
- require a new DTO freeze;
- require all Qt behavior to move behind `FrontendSessionAdapter`;
- require pixel or interaction parity between Qt and Tauri.
