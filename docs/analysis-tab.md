# Analysis Tab

## Purpose

The Analysis tab is a selected-flow analytical workspace.

## Principles

- selected-flow only
- on-demand
- ephemeral
- metadata-first

## Current blocks

- Overview, including timeline-oriented summary fields
- Protocol panel
- Derived metrics
- Directional stats
- Histograms for packet size and inter-arrival distribution
- Flow Rate graph
- Sequence preview
- Export sequence to CSV

## Data sources

- packet metadata only
- no payload bytes
- no reassembly

## UI behavior

- blocks are grouped with summary-oriented sections first and evidence/detail sections later
- work stays bounded and cheap enough for interactive selected-flow use
- no global computation is triggered across all flows

## Known limitations

- no percentiles
- no deep protocol analysis
- no cross-flow analysis