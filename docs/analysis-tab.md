# Analysis Tab

## Role

This document is the current technical feature contract for the `Analysis`
workspace in Pcap Flow Lab.

It describes what the Analysis workspace is today and the architectural
boundaries that keep it separate from `Statistics`, packet inspection, Stream,
and reassembly-oriented features.

End-user walkthroughs belong in [user_docs/ui/analysis.md](../user_docs/ui/analysis.md).

## Core contract

The Analysis workspace is:

- selected-flow only;
- on-demand;
- ephemeral/runtime-only;
- bounded to the currently selected canonical flow;
- based on imported flow/packet metadata rather than payload bytes.

Current behavior:

- Analysis targets exactly one selected canonical flow at a time.
- Results are computed on demand for the selected flow.
- Results are not precomputed during capture open/import.
- Results are not persisted into the analysis index or other
  durable capture state.
- Clearing or changing the selected flow discards the previous Analysis result.

Qt and Tauri both expose the Analysis workspace over the same shared backend
analysis result surface, while keeping frontend-local layout and rendering.

## Data-source boundary

Current production Analysis remains metadata-only.

It uses selected-flow packet metadata such as:

- packet timestamps;
- packet direction within the canonical flow;
- original packet length;
- captured packet length;
- packet-level transport/header facts already available in imported state;
- already derived flow-level protocol/service metadata.

It does not currently require:

- source payload bytes;
- payload parsing for Analysis-specific fields;
- selected-flow Stream reconstruction;
- reassembly-owned derived payload views.

This boundary is important: Analysis is adjacent to Stream, but it is not the
Stream subsystem and does not currently depend on Stream-style payload
materialization.

## Current visible blocks

Current Analysis exposes these blocks for the selected flow:

- `Overview`
- timeline/duration information within the overview
- `Protocol Panel`
- `Derived Metrics`
- `Directional`
- TCP control counts where relevant
- `Burst / Idle Summary`
- packet-size histogram
- inter-arrival histogram
- `Flow Rate`
- sequence preview
- sequence CSV export

## Current block semantics

### Overview

The overview summarizes the selected flow as a whole, including:

- endpoint summary;
- protocol/family summary fields where applicable;
- total packets;
- original bytes;
- captured bytes;
- first packet / last packet;
- duration;
- largest inter-packet gap;
- packets considered by the current analysis pass.

### Protocol information

The protocol panel is a bounded selected-flow summary surface, not a deep
payload dissection surface.

Current production exposes stable protocol-specific metadata when available,
including:

- TLS version or QUIC version where already derived from imported state;
- service/SNI-oriented fields where already carried by the current shared
  analysis/frontend result;
- TCP control counts (`SYN`, `FIN`, `RST`) when relevant to the selected flow.

### Derived metrics and directional statistics

Current derived metrics and directional statistics include:

- packets/sec;
- data rate;
- average packet size;
- average inter-arrival;
- min/max packet size;
- directional packet/byte counts;
- packet ratio / byte ratio;
- packet-direction / data-direction dominance summaries.

These remain selected-flow bounded metrics over imported packet metadata.

### Burst / idle metrics

Current production also exposes burst/idle summary metrics derived from the
selected flow's time-ordered packet sequence:

- burst count;
- longest burst packet count;
- largest burst bytes;
- idle gap count;
- largest idle gap.

### Histograms

Current production exposes:

- packet-size histogram;
- inter-arrival histogram.

Both histograms are derived from the selected flow only. Frontends may expose
direction-mode toggles over the shared histogram result sets.

### Flow Rate graph

Current production exposes a selected-flow `Flow Rate` graph using:

- `Data/s` and `Packets/s` metric modes;
- `A->B`, `B->A`, and `Both` direction modes;
- an automatic bounded aggregation window.

The graph remains selected-flow-only, metadata-only, and bounded.

### Sequence preview and export

Current production exposes:

- a bounded sequence preview for the selected flow;
- selected-flow sequence CSV export.

This is an Analysis-oriented ordered packet summary/export surface. It is not a
payload export surface.

## Architectural boundaries

Analysis must remain distinct from these neighboring systems:

- `Statistics` is capture-wide and summary-oriented.
- Packet Details is packet-selected inspection.
- Stream is selected-flow, payload-oriented, and may use bounded reconstruction
  for its own presentation.

Analysis may summarize one selected flow in more detail, but it does not imply
global analysis, global precompute, payload ownership, or reassembly-driven
inspection.

## Current limitations

- no cross-flow analysis;
- no persisted Analysis results;
- no Analysis-owned payload/reassembly interpretation layer;
- no requirement that every protocol expose extra protocol-panel metadata.
