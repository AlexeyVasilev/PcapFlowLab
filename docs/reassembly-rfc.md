# Reassembly RFC

## Status

Draft design note for future deep-analysis work. This document defines intended scope and integration boundaries. It does not authorize reassembly in the fast import path and it does not imply that current deep mode already performs stream reconstruction.

## Motivation

Packet-level parsing is already useful in Pcap Flow Lab, but it breaks down on common real captures once protocol metadata is split across multiple packets.

Practical examples in this project:
- HTTP request lines and headers may span several TCP segments, so packet-level parsing misses method, path, Host, or response status on otherwise normal traffic.
- TLS ClientHello metadata such as SNI may be present only after concatenating multiple TCP payload segments.
- QUIC Initial crypto data may require combining multiple packets before protocol-specific fields are available.

Reassembly in this project should solve a narrow problem first: improve deep-mode protocol analysis on realistic captures when single-packet decoding is insufficient, while keeping fast browsing predictable and cheap.

## Non-goals

The first implementation should explicitly avoid the following:
- no Wireshark-grade full-session reconstruction engine
- no reassembly work in fast import mode
- no broad generic framework that tries to solve every transport at once
- no lossless retransmission modeling in the first step
- no out-of-order correction in the first step
- no automatic retroactive reanalysis of all captures just because deep analysis exists
- no requirement to persist reassembled byte streams in indexes or checkpoints initially

## Reassembly Types Relevant Here

### TCP Stream Reassembly

Primary near-term target for richer HTTP and TLS analysis.

The useful unit for this project is not “entire connection forever”, but a bounded analyzer input built from packets belonging to a selected flow and direction. The first useful outcome is payload concatenation in packet order for a single direction. Control packets such as SYN or ACK without payload do not contribute bytes to that buffer; their existence may still matter for future metadata or debugging, but the first implementation may ignore them for simplicity.

### QUIC Initial Reassembly

QUIC should be treated separately from TCP stream reassembly.

The likely future need is limited crypto-frame reconstruction for Initial packets, not a generic full QUIC transport engine. This should stay analyzer-driven and deep-mode only.

### IPv4 Fragmentation

IPv4 fragmentation is a separate concern and should not be mixed into the first TCP/QUIC reassembly design.

If addressed later, it should be treated as packet reconstruction below transport analysis, with its own correctness and memory constraints.

## Architectural Placement

Reassembly must not live in the fast import path.

Current project structure already has a good separation point:
- fast import remains packet-metadata oriented and cheap
- deep mode is the place where richer analyzers can request more expensive derived artifacts
- `CaptureSession` is the right application-facing entry point for reassembly-backed reads

Planned relationship to existing layers:
- `core/decode` should remain packet-oriented and should not absorb stream logic
- `core/services` should host reassembly services because they already own payload extraction, deep protocol analyzers, and flow export logic
- `app/session/CaptureSession` should expose explicit deep-only read paths that can request reassembled data or analyzer results
- packet list and packet details should stay packet-based; reassembly should feed deep protocol outputs, not replace packet identity
- flow-level hints remain cheap single-packet metadata unless a future feature explicitly introduces deeper flow analysis

A reasonable shape is:
- packet-level import creates normal `CaptureState`
- deep analyzer requests a bounded reassembly artifact for one selected flow and direction
- analyzer consumes that artifact and returns protocol-specific results for UI or CLI presentation

The primary reassembly API should operate on `flow_id`, direction (`A→B` or `B→A`), and a bounded budget. In v1, analyzers should not manually assemble arbitrary packet sets; keeping the API flow-and-direction based makes the model easier to reason about.

Reassembly does not imply new top-level UI surfaces. It is expected to enhance existing deep-analysis outputs such as the Protocol tab and, where useful, the Payload tab, while the packet list remains packet-based.

## First Implementation Scope

Recommended first scope:
- selected flow only
- one direction only
- TCP payload concatenation in packet index order
- best-effort analyzer input only, not transport-correct byte-stream reconstruction
- bounded byte budget and/or packet budget per request
- analyzer-driven invocation from deep mode only

What this first scope should do:
- gather packets from `flow_a` or `flow_b`
- read transport payload bytes lazily from the capture via existing packet access
- concatenate payloads in packet order
- treat the result as a heuristic approximation only; packet-order concatenation is not a fully correct TCP byte stream, and analyzers must treat it as best-effort data
- expose enough data for common HTTP and TLS analysis on non-pathological captures

What it should not do yet:
- no retransmission detection
- no overlap trimming
- no out-of-order repair
- no bidirectional request/response stitching
- no persistence of large reconstructed buffers in saved indexes

This deliberately limited scope is enough to unlock noticeably better HTTP/TLS analysis while keeping the implementation understandable.

## Data Model Ideas

The first artifact should stay small and analyzer-oriented.

A practical conceptual model is:
- `ReassembledBuffer`
  - byte buffer
  - source packet refs or packet indices contributing to the buffer
  - direction metadata
  - lightweight quality flags such as `truncated_by_budget`, `packet_order_only`, `incomplete_transport`, and `may_contain_retransmissions`
  - truncation or byte-budget flag
- optional segment map later
  - per-segment source packet index
  - byte range in the reconstructed buffer
- optional gap markers later
  - indicate missing or skipped regions once retransmission/out-of-order handling exists

The important boundary is that reassembly should produce derived artifacts for analyzers, not mutate the underlying packet model. Those quality flags are primarily for analyzers; consumers must assume that a reassembled buffer may be incomplete or approximate.

## Performance And Reliability Constraints

Fast path requirements stay unchanged:
- no stream buffering during normal fast import
- no deep analyzer hooks in the hot ingestion loop beyond existing lightweight metadata work
- no hidden memory growth tied to capture size

Deep path requirements:
- deep analysis may be slower, but the cost must be explicit and localized to user-requested operations
- buffering must be bounded by policy, for example max packets per request and max reassembled bytes per request
- byte and packet budgets should be defined centrally as policy, not hardcoded independently inside analyzers
- v1 must not introduce persistent or session-wide reassembly caches; only request-scoped or per-selected-flow temporary buffering is allowed
- safe failure is preferable to partial garbage output
- analyzers should be told whether a buffer is complete, truncated by budget, or built under simplified ordering assumptions

## Future Evolution

Once the first minimal TCP reassembly exists, the likely next steps are:
- retransmission handling and overlap policy
- gap tracking and explicit incomplete-state reporting
- bidirectional stream views for request/response style protocols
- limited QUIC Initial crypto reassembly
- analyzer-specific reassembly strategies instead of one oversized generic engine
- optional caching of bounded deep-analysis artifacts when repeated reads justify it

Each of those should remain incremental and measurable. The project should not jump directly from packet parsing to a monolithic universal reassembly subsystem.

## Proposed Near-Term Integration Points

When implementation starts, the least disruptive entry points are likely:
- a new deep-only reassembly service in `core/reassembly`
- one or more `CaptureSession` helpers for selected-flow deep reads
- analyzer-specific use from HTTP and TLS deep protocol analysis first

This keeps the design aligned with current project priorities:
- predictable fast path
- conservative correctness
- explicit deep-only cost
- bounded memory behavior


