# Roadmap

This roadmap is an engineering roadmap for the current product direction.

It reflects what is already implemented, what is actively being stabilized, and what is planned next. It is intentionally practical rather than aspirational.

## Phase 1 — Core architecture (completed)

- packet-oriented fast path
- flow aggregation
- index support
- session/query API
- basic UI

This phase established the product's core architectural direction: bounded packet-oriented ingestion, flow-first state, and a separate application/UI layer over session queries.

## Phase 2 — Selected-flow views (completed)

- Stream (payload-oriented, selected-flow, on-demand)
- Analysis tab (metadata-first, selected-flow)
- Sequence preview
- Histograms and derived metrics
- Flow Rate graph

This phase established selected-flow, on-demand derived work as a first-class product direction without moving analysis or Stream reconstruction into global open-time processing.

## Phase 3 — Stream correctness (in progress)

- fixture-backed Stream baseline tests
- HTTP reassembly:
	- Content-Length support
	- chunked body support
- partial HTTP/TLS handling
- retransmission detection (selected-flow)
- retransmission suppression (in progress)

This phase is focused on making current Stream behavior more reliable and more test-backed before broadening protocol scope.

## Phase 4 — Stream model convergence (next)

- move Stream to a single bounded on-demand materialization model
- remove conceptual split between "prefix" and "full" Stream modes
- ensure `Load more` extends the same Stream build
- reduce user-visible differences between initial and expanded Stream results
- improve partial item consistency

This phase is about converging Stream behavior around one bounded selected-flow pipeline rather than preserving multiple conceptual Stream modes.

## Phase 5 — Protocol enrichment

- richer TLS details:
	- extensions
	- cipher suites
	- handshake fields
- QUIC stream labeling (narrow, bounded step)
- HTTP edge cases:
	- HEAD / 204 / 304
	- request bodies

This phase remains bounded and incremental. Protocol work is expected to stay conservative and test-backed rather than aiming for broad, fragile coverage.

## Phase 6 — UI and usability

- Stream details UX improvements
- packet/stream consistency
- better loading states for large flows
- Wireshark integration helpers

This phase is focused on making the existing selected-flow workflows easier to understand and more predictable during interactive use.

## Phase 7 — Scalability and performance

- selected-flow scalability improvements
- incremental loading stability
- mmap evaluation (optional)
- large capture handling improvements

This phase is focused on preserving bounded interactive behavior as capture size and selected-flow size increase.

## Roadmap priorities

The roadmap prioritizes:

- reliability over feature count
- bounded computation
- selected-flow on-demand architecture
- test-backed evolution

Do not introduce multiple Stream modes or global reassembly in any phase.
