# Analysis Tab RFC

## Purpose

This RFC defines the Analysis tab as a per-flow, on-demand, ephemeral analysis workspace.

Analysis is a user-facing analytical view over the currently selected connection. It is not a global precompute system, not part of capture open or import, and not part of persisted session or index state.

The goal is to fix the architectural direction now that an initial MVP implementation exists in service, session/controller wiring, and UI.

## Status

An initial MVP implementation already exists.

- a per-flow analysis service
- session and controller wiring for selected-flow access
- an initial Analysis tab in the flow workspace UI

This RFC defines the intended boundaries for further expansion so the feature remains consistent with the existing packet-oriented fast path and selected-flow analysis model.

## Goals

- define Analysis as selected-flow scoped rather than capture-wide
- keep analysis on demand rather than part of open/import
- keep derived analysis state ephemeral rather than persisted
- keep the initial phase bounded, simple, and based on already available metadata
- preserve architectural consistency with Stream and other selected-flow features

## Non-goals

- no global analysis across all flows
- no analysis precompute during capture open
- no persistence of analysis results into index, checkpoint, or session state
- no hidden background precompute after open
- no immediate ML integration
- no requirement to mirror Wireshark feature-for-feature
- no conversion of the product into a generic analytics platform

## Architectural alignment

This RFC must remain aligned with the existing project architecture.

- fast path remains packet-oriented
- open/import remains focused on packet, flow, summary, and hint derivation that is already part of the current model
- selected-flow deep or derived views remain on demand
- bounded derived artifacts remain ephemeral
- Stream already follows this model for selected-flow payload-oriented inspection
- Analysis tab follows the same selected-flow philosophy

Analysis must therefore remain outside capture open, outside index building, and outside checkpoint persistence.

## Analysis workspace model

The Analysis tab is a workspace for the currently selected flow.

- scope is exactly one selected connection at a time
- output is derived from existing imported state and, when needed later, bounded selected-flow reads
- results may be rebuilt whenever selection changes
- results may be discarded at any time
- analysis state is not part of durable system state

This is intentionally different from capture-wide statistics or future cross-flow reporting. The Analysis tab is about understanding one selected flow in more detail, on demand.

## MVP scope

The initial MVP scope is intentionally narrow.

### Overview

- duration
- total packets
- total bytes
- protocol hint
- service hint

### Directional stats

- packets `A->B` / `B->A`
- bytes `A->B` / `B->A`

MVP analysis should rely only on already available flow metadata and packet references.

- no reassembly is required
- no payload-derived workspace state is required
- no new open-time analysis is required

This keeps the first phase cheap, deterministic, and consistent with the existing architecture.

## Bounded analysis contract

All Analysis tab work must be bounded.

- by the number of packets examined
- by the amount of data processed
- by execution time expectations suitable for interactive use

No phase is allowed to introduce unbounded scanning of a flow.

Future phases such as timeline, histograms, or protocol panels must:

- define their bounds explicitly
- remain suitable for interactive use

This is consistent with the project's existing bounded reassembly principles: selected-flow derived work may be useful and best-effort, but it must not become unbounded in latency or resource use.

## Partial and approximate results

Analysis results may be:

- partial, due to explicit bounds
- approximate, due to heuristic methods
- truncated, due to limits

The UI must treat these results as best-effort rather than ground truth.

Analysis must prefer safe partial output over blocking or attempting full reconstruction.

## Data-source tiers

Future Analysis tab work may use more than one source tier, but the tiers must stay explicit.

### Tier 1

Flow metadata and packet references only.

Examples:

- packet counts
- byte counts
- first/last packet timing
- already derived protocol or service hints

### Tier 2

Packet-header level access when needed later.

Examples:

- transport flag summaries
- packet-size and inter-arrival derived views
- bounded header-level classification hints

### Tier 3

Payload or bounded reassembly assisted analysis when needed later.

Examples:

- protocol-specific panels that need payload context
- bounded payload-derived hints
- narrowly scoped reassembly-assisted interpretation

MVP stays entirely in Tier 1.

## Trigger model

Analysis is refreshed only for the currently selected flow.

- changing the selected flow refreshes the selected-flow analysis state
- no global analysis runs across all flows
- no background global analysis is introduced

The active Analysis tab is the natural trigger point for heavier future analysis phases.

That means:

- cheap Tier 1 analysis may be refreshed immediately for the selected flow
- heavier future phases should be allowed to run only when Analysis is the active tab or when the user explicitly requests them
- flow selection alone must not become a hidden trigger for expensive deep analysis

This keeps the model simple and consistent with existing selected-flow behavior.

## Execution model

For MVP, synchronous execution is acceptable if the work remains cheap.

The current Tier 1 scope is small enough that a synchronous selected-flow refresh is reasonable.

Analysis execution must remain observable to the user.

Future heavier phases may require:

- async execution
- loading state
- cancellation or replacement when selection changes

For heavier phases:

- the UI should show loading state
- results should appear progressively or after completion
- selection change must cancel or replace ongoing analysis
- stale or misleading results must be avoided

This RFC does not fix an async design yet. It only fixes the requirement that heavier selected-flow analysis must remain observable and must not silently turn into blocking global work.

## Cache and persistence policy

Analysis results are not persisted.

- no persistence into `CaptureState`
- no persistence into index files
- no persistence into checkpoints
- no saved analysis workspace state for a flow

Cache, if any, is only for the currently selected flow.

- it is a UI or performance optimization only
- it may be discarded at any time
- it must not become a hidden cross-flow cache
- it must not imply precompute during open

## Phase plan

### Phase 1

- Overview
- Directional stats

### Phase 2

- Timeline
- Sequence preview

### Phase 3

- Packet size histogram
- Inter-arrival histogram

### Phase 4

- Protocol panels
- Derived hints
- simple classification hints

Each phase must remain bounded, selected-flow scoped, and on demand.

No phase is allowed to expand the feature into hidden global background analysis.

## Explicit exclusions

The Analysis tab must not grow into the following:

- global analysis over all flows
- persistence into index or checkpoint state
- hidden background precompute during open
- immediate ML-driven classification pipeline
- an attempt to replicate Wireshark feature-for-feature

If future analysis becomes expensive, the correct response is bounded, observable, selected-flow execution, not architecture drift into global precomputation.

## Relationship to existing features

The project already distinguishes between durable packet/flow state and selected-flow derived views.

- fast path remains packet-oriented and durable where appropriate
- Stream remains selected-flow, ephemeral, and bounded
- Analysis tab follows the same pattern for analytical views over one selected connection

The two selected-flow views serve different purposes.

- Stream is payload-oriented and may use bounded reassembly
- Analysis is a statistics and analytical view that starts metadata-only and may optionally use bounded deeper analysis later

Analysis must not duplicate Stream behavior.

This RFC therefore fixes Analysis as another selected-flow workspace layer over existing imported state, not as a new global analysis subsystem.