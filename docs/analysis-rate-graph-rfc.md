# Analysis Rate Graph RFC

## Purpose

This RFC defines a Flow Rate Graph block for the Analysis tab.

The block is:

- selected-flow only
- on-demand
- ephemeral
- metadata-only
- not persisted
- not part of open/import/index

The Flow Rate Graph is a bounded analytical view for one selected connection. It is not a general charting framework and not a global precompute feature.

## Metrics and Modes

MVP supports two metrics:

- `Data/s`
- `Packets/s`

MVP supports three direction modes:

- `A->B`
- `B->A`
- `Both`

For `Both`, the graph renders two lines at the same time, one per direction.

## Data Source

The graph must use only:

- packet timestamps
- packet lengths
- packet direction

The graph must not use:

- payload bytes
- reassembly
- protocol-specific parsing

## Axes

X axis:

- relative time since the first packet in the selected flow
- monotonic increasing

Y axis:

- selected metric (`Data/s` or `Packets/s`)
- computed per aggregation window

## Aggregation Model

The graph is defined as time-windowed aggregation, not packet-by-packet plotting.

For each window:

- `Data/s = bytes_in_window / window_duration_seconds`
- `Packets/s = packets_in_window / window_duration_seconds`

This keeps the graph stable and cheap enough for interactive selected-flow analysis.

## Window Selection

MVP window selection is adaptive and bounded.

Recommended strategy:

- choose a target point count around `60`
- compute `window = flow_duration / target_point_count`
- clamp to fixed bounds: minimum `10 ms`, maximum `1 s`
- enforce a hard point cap of `<= 100`

The UI should show the effective window size, for example:

- `Window: 50 ms (auto)`

This keeps behavior deterministic and avoids a hardcoded one-size-fits-all interval.

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

MVP must not rely on a hardcoded `2 seconds` rule.

Instead, if the selected flow cannot produce enough useful points with the bounded window strategy, show a fallback message such as:

- `Flow too short for rate graph`

No synthetic or misleading line should be rendered in this case.

## Rendering Strategy

For MVP, prefer a lightweight custom QML-rendered line graph.

Do not add Qt Charts/Graphs dependencies unless later profiling proves a clear need.

MVP rendering scope is intentionally narrow:

- one-line rendering
- two-line rendering for `Both`
- simple bounded point count
- no advanced interactions

## UI Shape

Flow Rate block shape:

- title: `Flow Rate`
- metric selector: `[ Data/s | Packets/s ]`
- direction selector: `[ A->B | B->A | Both ]`
- supporting text: effective auto-selected window size

Color usage should match existing direction semantics:

- `A->B = green`
- `B->A = blue`

The block should remain compact and consistent with current Analysis tab layout.

## Performance Constraint

Computation must be:

- `O(N)` in packets of the selected flow
- independent from total capture size

The graph must remain selected-flow scoped and bounded.

## Non-Goals (Phase 1)

Phase 1 explicitly excludes:

- zoom/pan
- scrollable time navigation
- manual free-form window input
- smoothing/interpolation
- stacked area charts
- hover tooltips
- persistent graph state
- chart-library abstraction framework

## Future Directions

Potential later extensions:

- zoom presets
- hover/cursor values
- export of aggregated rate series
- optional `All` mode if later justified

These are out of Phase 1 scope.

## Consistency With Current Architecture

This block must follow the existing architecture boundaries:

- fast path stays packet-oriented
- Analysis remains selected-flow, on-demand, ephemeral
- Stream/reassembly boundaries remain unchanged

The rate graph is a bounded selected-flow analysis block, not a new global analysis subsystem.
