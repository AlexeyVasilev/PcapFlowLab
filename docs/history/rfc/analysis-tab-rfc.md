# Analysis Tab RFC

## Status

Status: Implemented design RFC / historical design context

The selected-flow Analysis workspace described here has been implemented.

For the current technical contract, use:

- [analysis-tab.md](../../analysis-tab.md)
- [ui/presentation_contract.md](../../ui/presentation_contract.md)

This RFC is retained to preserve the architectural rationale and staged design
reasoning behind the Analysis workspace. Historical references to MVP scope,
future phases, or later expansion should be read as design-evolution context,
not as the current product contract.

## Purpose

This RFC defines the Analysis tab as a per-flow, on-demand, ephemeral analysis
workspace.

Analysis is a user-facing analytical view over the currently selected
connection. It is not a global precompute system, not part of capture open or
import, and not part of persisted session or index state.

The goal of this RFC was to fix the architectural direction so the feature
would remain consistent with the existing packet-oriented fast path and
selected-flow analysis model.

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

This RFC was written to remain aligned with the existing project architecture.

- fast path remains packet-oriented
- open/import remains focused on packet, flow, summary, and hint derivation
  that is already part of the current model
- selected-flow deep or derived views remain on demand
- bounded derived artifacts remain ephemeral
- Stream already follows this model for selected-flow payload-oriented inspection
- Analysis tab follows the same selected-flow philosophy

Analysis must therefore remain outside capture open, outside index building,
and outside checkpoint persistence.

## Analysis workspace model

The Analysis tab is a workspace for the currently selected flow.

- scope is exactly one selected connection at a time
- output is derived from existing imported state and, when needed later,
  bounded selected-flow reads
- results may be rebuilt whenever selection changes
- results may be discarded at any time
- analysis state is not part of durable system state

This is intentionally different from capture-wide statistics or future
cross-flow reporting. The Analysis tab is about understanding one selected flow
in more detail, on demand.

## Historical initial scope

The initial MVP scope was intentionally narrow.

### Overview

- duration
- total packets
- total bytes
- protocol hint
- service hint

### Directional stats

- packets `A->B` / `B->A`
- bytes `A->B` / `B->A`

The initial implementation was intended to rely only on already available flow
metadata and packet references.

- no reassembly is required
- no payload-derived workspace state is required
- no new open-time analysis is required

That kept the first phase cheap, deterministic, and consistent with the
existing architecture.

## Bounded analysis contract

All Analysis tab work must be bounded.

- by the number of packets examined
- by the amount of data processed
- by execution time expectations suitable for interactive use

No phase is allowed to introduce unbounded scanning of a flow.

Later additions such as timeline, histograms, or protocol panels were intended
to:

- define their bounds explicitly
- remain suitable for interactive use

This is consistent with the project's existing bounded reassembly principles:
selected-flow derived work may be useful and best-effort, but it must not
become unbounded in latency or resource use.

## Partial and approximate results

Analysis results may be:

- partial, due to explicit bounds
- approximate, due to heuristic methods
- truncated, due to limits

The UI must treat these results as best-effort rather than ground truth.

Analysis must prefer safe partial output over blocking or attempting full
reconstruction.

## Data-source tiers

This RFC preserved an explicit tier model so later Analysis evolution would not
blur the boundary between metadata-first analysis and deeper payload-oriented
inspection.

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

The initial production Analysis workspace stayed entirely in Tier 1. Current
production still follows a metadata-only Analysis model rather than a
payload/reassembly-driven one.

## Trigger model

Analysis is refreshed only for the currently selected flow.

- changing the selected flow refreshes the selected-flow analysis state
- no global analysis runs across all flows
- no background global analysis is introduced

The active Analysis tab was treated as the natural trigger point for any
heavier later analysis phases.

That means:

- cheap Tier 1 analysis may be refreshed immediately for the selected flow
- heavier later phases should be allowed to run only when Analysis is the
  active tab or when the user explicitly requests them
- flow selection alone must not become a hidden trigger for expensive deep
  analysis

This keeps the model simple and consistent with existing selected-flow
behavior.

## Execution model

For the initial implementation, synchronous execution was acceptable as long as
the work remained cheap.

The current Tier 1 scope was small enough that a synchronous selected-flow
refresh was reasonable.

Analysis execution must remain observable to the user.

Heavier later phases may require:

- async execution
- loading state
- cancellation or replacement when selection changes

For heavier phases:

- the UI should show loading state
- results should appear progressively or after completion
- selection change must cancel or replace ongoing analysis
- stale or misleading results must be avoided

This RFC did not fix an async design. It only fixed the requirement that
heavier selected-flow analysis must remain observable and must not silently
turn into blocking global work.

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

## Historical phase plan

This phase plan is preserved as historical design scaffolding. Current
production has since implemented more than the earliest slice originally called
out here, but the preserved sequence is still useful for understanding the
intended evolution constraints.

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

Each phase was intended to remain bounded, selected-flow scoped, and on
demand.

No phase is allowed to expand the feature into hidden global background
analysis.

## Explicit exclusions

The Analysis tab must not grow into the following:

- global analysis over all flows
- persistence into index or checkpoint state
- hidden background precompute during open
- immediate ML-driven classification pipeline
- an attempt to replicate Wireshark feature-for-feature

If future analysis becomes expensive, the correct response is bounded,
observable, selected-flow execution, not architecture drift into global
precomputation.

## Relationship to existing features

The project already distinguishes between durable packet/flow state and
selected-flow derived views.

- fast path remains packet-oriented and durable where appropriate
- Stream remains selected-flow, ephemeral, and bounded
- Analysis tab follows the same pattern for analytical views over one selected
  connection

The two selected-flow views serve different purposes.

- Stream is payload-oriented and may use bounded reassembly
- Analysis is a statistics and analytical view that starts metadata-only and may
  optionally use bounded deeper analysis later

Analysis must not duplicate Stream behavior.

This RFC therefore fixed Analysis as another selected-flow workspace layer over
existing imported state, not as a new global analysis subsystem.
