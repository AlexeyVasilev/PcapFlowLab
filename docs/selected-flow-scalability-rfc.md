# Selected-Flow Scalability RFC

## Purpose

This RFC covers two practical problems that now matter for large captures.

### Selected-flow scalability

Selecting a flow with many packets can stall the UI because too much packet and Stream materialization happens at once.

Likely causes in the current model:

- packet rows may be materialized too eagerly for a large selected flow
- Stream items may be built too eagerly for the selected flow
- lazy packet-byte reads or packet parsing may still happen for too many items at once
- the UI can look hung because it has no explicit per-flow loading state

### Partial-open behavior

Large captures may fail after a substantial valid prefix has already been parsed.

Today, open still behaves as a fatal failure even when a large internally consistent prefix was imported successfully. That can discard useful work and makes debugging large-file behavior harder.

This RFC defines a minimal path for keeping selected-flow interaction responsive and for deciding when a partial import may still be usable with an explicit warning.

## Goals

- keep flow selection responsive even for very large flows
- bound packet and Stream materialization triggered by flow selection
- make long per-flow loading observable to the user
- avoid eager parsing of all packets in a selected flow
- define safe conditions for partial open with warning
- preserve current architecture boundaries

## Non-goals

- no global precompute across all flows
- no pagination-first redesign
- no persistence of Stream artifacts
- no automatic deep parsing of every packet in a selected flow
- no full TCP, HTTP, TLS, or QUIC correctness as part of this RFC
- mmap is not the primary solution addressed here

## Architectural boundaries

This RFC must remain aligned with the current architecture.

- fast open remains packet-oriented
- index workflow remains the durable path for reused analysis state
- on-demand Stream analysis remains selected-flow scoped
- reassembly remains bounded and ephemeral
- no global analysis is added to open
- no Stream artifacts become persistent

## Selected-flow loading model

Selecting a flow must stay cheap.

Heavy per-flow work must be incremental and bounded rather than performed as one large synchronous materialization step.

The recommended model is split into three layers.

### Immediately available data

Available as soon as the flow is selected:

- flow summary
- cheap flow metadata already present in session state
- any already prepared counts or hints that do not require packet-byte reads

### Bounded initial materialization

Prepared first, with explicit limits:

- first `N` packet rows
- first `M` Stream items

This initial step should be small enough that flow selection still feels responsive.

### Incremental expansion

Remaining packet rows or Stream items are prepared later:

- on demand
- or in bounded follow-up steps

This RFC does not require a specific UI control yet. The key rule is that heavy selected-flow work must be incremental and bounded.

## Expected UI behavior for heavy flows

The UI should make long selected-flow work visible instead of looking frozen.

Recommended behavior:

- show `Loading packets...` while packet rows are being prepared
- show `Loading stream...` while Stream items are being prepared
- allow initial partial content to appear before full materialization completes
- provide a path for bounded continuation or `load more` later

The user should be able to tell the difference between:

- no data
- partial data still loading
- completed initial materialization

## Partial-open policy

Partial open should be a narrow, explicit mode rather than an implicit side effect.

Recommended policy: `partial_success_with_warning` is allowed only when the imported prefix is internally consistent.

Required conditions:

- failure occurs at the next unread or unaccepted packet or block
- no earlier parser desynchronization is tolerated
- already imported flows, packet references, and summaries remain internally consistent as a prefix view
- the system can describe clearly that import stopped early and results are incomplete

If those conditions are not met, open remains a normal fatal failure.

## Partial-open UX expectations

If partial open is allowed, the UI should present it explicitly.

Recommended behavior:

- show a clear warning banner
- state that import stopped early
- explain that capture results are incomplete
- preserve the distinction between a full open and a partial open

Initial restrictions are expected.

A practical first restriction is that saving an index from a partial capture may remain disabled until the policy is defined more fully.

## Observability and loading states

Selected-flow work should be observable for the same reason full open is now observable.

Recommended direction:

- packet materialization and Stream materialization should expose loading state
- the UI should be able to show that a large selected flow is still being prepared
- observability should be lightweight and should not require global precompute

This is about responsiveness and clarity, not about adding deep analysis during selection.

## Relationship to mmap and chunked import

This RFC is not primarily about mmap.

- mmap may later help random-access packet reads if profiling justifies it
- chunked import remains a separate future direction
- neither is the first solution to selected-flow stalls addressed here

The first solution remains bounded and incremental selected-flow loading.

## Implementation phases

### Phase 1

- selected-flow loading states in the UI
- observability for packet and Stream materialization

### Phase 2

- bounded initial packet-list materialization

### Phase 3

- bounded initial Stream materialization

### Phase 4

- incremental continuation or `load more` behavior

### Phase 5

- partial-open-with-warning implementation

## Known risks and tradeoffs

- a bounded initial view may not show all packets or Stream items immediately
- Stream view may still differ from Wireshark in edge cases because reassembly remains bounded and heuristic
- partial-open support increases product-state complexity and must stay strict about prefix consistency

These tradeoffs are acceptable only if they keep the product responsive and the data model honest.