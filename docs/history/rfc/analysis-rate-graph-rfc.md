# Analysis Rate Graph RFC

## Status

Status: Implemented design RFC / historical design context

The selected-flow `Flow Rate` block described here has been implemented.

For the current Analysis feature contract and shared UI semantics, use:

- [analysis-tab.md](../../analysis-tab.md)
- [ui/presentation_contract.md](../../ui/presentation_contract.md)

This RFC is retained to preserve the design rationale and constraints that led
to the current rate-graph implementation. Historical references to MVP or
later directions should be read as implemented-design context, not as an active
implementation plan.

## Purpose

This RFC defines a Flow Rate Graph block for the Analysis tab.

The block is:

- selected-flow only
- on-demand
- ephemeral
- metadata-only
- not persisted
- not part of open/import/index

The Flow Rate Graph is a bounded analytical view for one selected connection.
It is not a general charting framework and not a global precompute feature.

## Metrics and Modes

The initial design targeted two metrics:

- `Data/s`
- `Packets/s`

The initial design targeted three direction modes:

- `A->B`
- `B->A`
- `Both`

For `Both`, the graph renders two lines at the same time, one per direction.

Current production still follows this high-level mode model.

## Data Source

The graph is defined to use only:

- packet timestamps
- packet lengths
- packet direction

The graph is defined not to use:

- payload bytes
- reassembly
- protocol-specific parsing

Current production remains aligned with that metadata-only boundary.

## Axes

X axis:

- relative time since the first packet in the selected flow
- monotonic increasing

Y axis:

- selected metric (`Data/s` or `Packets/s`)
- computed per aggregation window

## Aggregation Model

The graph is defined as time-windowed aggregation, not packet-by-packet
plotting.

For each window:

- `Data/s = bytes_in_window / window_duration_seconds`
- `Packets/s = packets_in_window / window_duration_seconds`

This keeps the graph stable and cheap enough for interactive selected-flow
analysis.

## Window Selection

The implemented graph uses adaptive bounded window selection, but not every
historical recommendation here remained identical in final production.

Historical design recommendation:

- choose a target point count around `60`
- compute `window = flow_duration / target_point_count`
- clamp to fixed bounds: minimum `10 ms`, maximum `1 s`
- enforce a hard point cap of `<= 100`

The UI should show the effective window size, for example:

- `Window: 50 ms (auto)`

Current production keeps the same overall design direction:

- auto-selected bounded windowing
- minimum `10 ms` and maximum `1 s` clamps
- bounded point count
- no manual free-form window control

One notable implementation difference is that current production targets a
higher point budget than the early RFC recommendation, while still enforcing a
hard bounded graph size.

## Window Semantics and Packet Assignment

Window behavior is deterministic:

- windows are contiguous
- windows are non-overlapping
- windows start at the first packet timestamp of the selected flow

Packet assignment is deterministic:

- each packet belongs to exactly one window
- assignment is based on packet timestamp

## Directional Series Computation

Directional series are computed independently.

- `A->B` uses only packets in direction `A->B`
- `B->A` uses only packets in direction `B->A`

In `Both` mode, both directional series are rendered together.

## Y-Axis Scaling

Y-axis scaling is auto-selected per graph.

- max Y value is based on visible aggregated data
- in `Both` mode, both lines must share the same Y scale

## Short-Flow Fallback

The implemented design did not rely on a hardcoded `2 seconds` rule.

Instead, if the selected flow cannot produce enough useful points with the
bounded window strategy, the graph may show a fallback message such as:

- `Flow too short for rate graph`

No synthetic or misleading line should be rendered in this case.

## Rendering Strategy

The original design preferred a lightweight custom-rendered graph rather than a
heavy charting dependency.

The initial rendering scope was intentionally narrow:

- one-line rendering
- two-line rendering for `Both`
- simple bounded point count
- no advanced interactions

The current product continues to treat this as a compact bounded Analysis block
rather than as a general charting subsystem.

## UI Shape

Flow Rate block shape:

- title: `Flow Rate`
- metric selector: `[ Data/s | Packets/s ]`
- direction selector: `[ A->B | B->A | Both ]`
- supporting text: effective auto-selected window size

Color usage should match existing direction semantics:

- `A->B = green`
- `B->A = blue`

The block was intended to remain compact and consistent with the Analysis
workspace layout.

Current production exposes the graph in both Qt and Tauri over the same shared
analysis result surface, while each frontend keeps its own rendering details.

## Performance Constraint

Computation must be:

- `O(N)` in packets of the selected flow
- independent from total capture size

The graph must remain selected-flow scoped and bounded.

## Historical non-goals

The initial phase explicitly excluded:

- zoom/pan
- scrollable time navigation
- manual free-form window input
- smoothing/interpolation
- stacked area charts
- hover tooltips
- persistent graph state
- chart-library abstraction framework

## Historical future directions

Potential later extensions considered during design:

- zoom presets
- hover/cursor values
- export of aggregated rate series
- optional `All` mode if later justified

These ideas are preserved as historical design context, not as the current
feature contract.

## Consistency With Current Architecture

This block follows the same architecture boundaries as the broader Analysis
workspace:

- fast path stays packet-oriented
- Analysis remains selected-flow, on-demand, ephemeral
- Stream/reassembly boundaries remain unchanged

The rate graph is a bounded selected-flow analysis block, not a new global
analysis subsystem.
