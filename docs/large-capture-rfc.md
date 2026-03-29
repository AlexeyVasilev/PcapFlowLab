# Large Capture Handling RFC

## Purpose

Pcap Flow Lab already has a workable architecture for capture import, saved indexes, and on-demand Stream analysis, but large capture handling is still underdefined from a user and operational perspective.

Problems visible today:

- opening a large capture is effectively a black-box operation
- the UI has no explicit progress model for long opens
- the user cannot cancel an open in progress
- console logging is not clearly separated into normal runtime output vs developer diagnostics
- UI behavior for very large flow and packet lists is not yet an explicit architectural concern

This RFC defines a minimal evolution path for large-file handling that stays consistent with the current packet-oriented fast path, index workflow, and flow-local on-demand analysis model.

## Goals

- make long-running open operations observable through progress reporting
- support safe cancellation of long-running operations
- improve performance visibility and regression tracking
- define a scalable UI direction for very large flow and packet lists
- stay compatible with later large-file features such as chunked import resume and optional mmap-backed access

## Non-goals

- no full TCP-correct reconstruction
- no global reassembly during open
- no database backend
- no immediate pagination-first redesign of the UI
- no full HTTP, TLS, or QUIC protocol completeness
- no distributed or multi-node processing

## Open Lifecycle Model

Large capture opening should be modeled explicitly as a job rather than treated as an opaque blocking action.

Conceptual shape:

- `idle`
- `running`
- `cancelling`
- `completed`
- `failed`
- `cancelled`

Implications:

- the application layer initiates an `OpenCaptureJob`
- the UI observes job state instead of assuming that open is instantaneous
- success and failure are explicit terminal states
- cancellation is also an explicit terminal state, not an implicit failure

This does not require a full background-task framework in the first step. The key architectural change is to define open as an observable operation with lifecycle state.

## Execution Model (Minimal)

`OpenCaptureJob` is expected to run outside the UI thread.

UI thread:

- initiates the job
- observes progress and lifecycle state

Worker context:

- performs ingestion
- reports progress
- checks cancellation

The exact threading model is implementation-defined and is intentionally not fixed by this RFC.

## Progress Model

Progress should be approximate, monotonic, and cheap to measure.

Preferred progress signals:

- bytes processed
- packets processed
- optional percentage when total file size is known

Requirements:

- progress reporting must not introduce heavy per-packet overhead
- progress values should move forward monotonically
- percentage should be treated as approximate for formats where exact forward progress is harder to express
- progress updates should be rate-limited or batched to avoid excessive synchronization or UI overhead
- examples include updating every N packets or every M milliseconds

The goal is operational visibility, not perfect accounting.

## Cancellation Model

Cancellation should be cooperative.

Conceptual model:

- a shared `cancel_requested` flag is set by the caller
- ingestion checks that flag only at safe points

Example safe points:

- after packet read
- after chunk processing
- after batch aggregation

Requirements:

- cancellation must leave the application in a valid state
- partially opened captures are discarded unless a future feature explicitly supports partial retention
- cancellation should transition through `cancelling` to `cancelled`
- cancellation must not corrupt in-memory state, indexes, or checkpoints
- cancellation must not leave partially visible or inconsistent data in UI-visible collections
- all observable state must remain valid and internally consistent after cancellation

## Logging Policy

Logging for large-file workflows should be split cleanly between normal runtime behavior and developer diagnostics.

Default runtime policy:

- minimal or no console logging during open
- no noisy per-packet or per-batch console output

Developer policy:

- explicit opt-in logging only
- existing `perf-open.enabled` CSV logging remains the supported regression-tracking mechanism for open-time performance

Requirements:

- logging must not materially affect large-file performance
- developer logging must remain clearly separate from user-facing behavior

## UI Scalability

Large flow and packet lists must be treated as scalability-sensitive UI surfaces.

Preferred direction:

- virtualization or lazy rendering
- scroll-based navigation is acceptable
- avoid eager full materialization of visible delegates

Explicit policy:

- pagination is not the primary approach at this stage
- the first goal is to keep existing list-style workflows usable at larger scales

This RFC does not prescribe a specific Qt Quick control strategy yet. It defines the requirement that the UI layer must scale without forcing a pagination-first product model.

## MMAP Strategy

Memory mapping should be treated as an optional backend optimization, not a mandatory architectural dependency.

Recommended direction:

- introduce or preserve a `ByteSource`-style abstraction for packet-data access
- allow mmap-backed random access behind that abstraction where it is beneficial
- keep sequential ingestion independent from mmap

Rationale:

- mmap can help random-access packet reads for details, payload, export, and other lazy paths
- sequential ingestion does not require mmap to be architecturally valid
- mmap adoption should be incremental, measurable, and reversible
- mmap must not be required for correctness
- the system must remain fully functional with non-mmap backends

## Future: Chunked Import

Chunked import remains a future direction for very large captures.

Potential scope:

- staged processing over large inputs
- resume capability
- later merge/finalize of partial results

Important boundary:

- this is not the current implementation
- it requires separate design work around state boundaries, result merging, and UX

## Implementation Phases

Recommended order:

### Phase 1

- quiet default logging
- progress reporting for open operations

### Phase 2

- cooperative cancellation support

### Phase 3

- UI scalability validation for large flow and packet lists

### Phase 4

- optional mmap-backed random-access data path

### Phase 5

- future chunked import and resume evolution

This order keeps the first changes low-risk and user-visible without expanding protocol scope.

## Consistency With Existing Architecture

This RFC is intentionally aligned with the current system boundaries.

- the fast path remains packet-oriented
- reassembly remains on-demand and flow-local
- open does not grow into global stream analysis
- no stream artifacts are persisted
- index-based workflows remain the durable path for reused analysis state

Large-capture support should improve observability, cancellation, and scalability without changing those core boundaries.


