# Bounded TLS Open-Time Hinting RFC

Status: Current.

This document describes the current bounded import-time TLS ClientHello SNI
continuation behavior. It is intentionally narrower than selected-flow TLS
reconstruction and does not define general TCP reassembly.

## Purpose

Current packet-local TLS open-time hinting can extract SNI when the relevant
ClientHello bytes are already available in the first TCP segment.

A common missed case is:

- TCP segment 1 contains the TLS record header and the start of a ClientHello,
  but the SNI bytes are not yet present.
- TCP segment 2 is the contiguous continuation and contains the SNI extension.

Current import can detect TLS from the first segment and recover the SNI during
open when the second segment is the exact contiguous same-direction continuation.

This behavior recovers SNI during raw-capture import for this common
two-contiguous-segment case without adding general TCP reassembly to the open
path.

## Non-Goals

This is not:

- general TCP reassembly
- a TCP stream engine
- 3+ TCP segment ClientHello reconstruction
- retransmission repair
- overlap repair
- gap recovery
- out-of-order recovery
- arbitrary TLS record-stream reconstruction
- TLS handshake reconstruction across multiple TLS records
- a replacement for selected-flow TLS reconstruction

Prefer false negatives over broader state or reassembly complexity.

## Open-Time Fast Path

Packet-local detection remains the common path.

If packet-local ClientHello parsing already finds SNI, use it immediately and
allocate no continuation state. Ordinary TCP packets must not probe the sparse
continuation store.

A pending candidate may be created only when all of the following are true:

- terminal protocol is TCP
- TLS record header is complete and valid
- TLS ContentType is Handshake
- complete TLS handshake header is available
- Handshake Type is ClientHello
- declared record and handshake lengths are plausible
- ClientHello logically belongs to this TLS record
- ClientHello is incomplete in the current TCP payload
- SNI has not already been extracted
- the current terminal TCP segment is fully captured, not snaplen-truncated

Do not retain:

- only a TLS record header
- a partial handshake header
- a non-ClientHello handshake
- complete ClientHello without SNI
- complete ClientHello with SNI
- snaplen-truncated first TCP segments

## Connection Marker

The intended hot-state marker lives in `ConnectionHintSearchState` and is
runtime-only.

Logical states are:

- no pending TLS ClientHello
- `flow_a` pending, remaining budget 1..3
- `flow_b` pending, remaining budget 1..3

The intended representation is one byte if implementation layout permits it.
The RFC does not freeze specific bit values.

Callers should use helper APIs instead of magic encoded values.

Direction rule:

- `Connection::flow_a` / `flow_b` means first-observed directional Flow and is
  the required direction identity for this feature.
- Do not use `resolve_direction(ConnectionKey, FlowKey)` as a substitute,
  because that direction is relative to canonical sorted `ConnectionKey`
  endpoints.

Recommended helper:

- `ConnectionFlowSlot { none, flow_a, flow_b }`
- resolution based on the actual `Connection` flow keys

## Sparse Retained State

Actual retained ClientHello prefix bytes live in import-scoped sparse storage
owned by `FlowHintService`.

Use separate IPv4 and IPv6 maps keyed by directional `FlowKeyV4` and
`FlowKeyV6`.

A conceptual entry contains:

- retained TCP payload prefix bytes
- expected next TCP sequence number
- expected ClientHello end or equivalent bounded metadata

Only one pending candidate is allowed per bidirectional `Connection`.

Marker/store invariant:

- marker absent: sparse store must not be probed
- marker present: sparse entry is expected

If a marker exists but the sparse entry is missing, clear the marker and accept
a false negative. Do not perform expensive repair.

## Budget 3 State Machine

After retaining the first ClientHello segment:

- remaining same-direction packet budget is 3
- the packet that creates the pending candidate does not consume the budget

Opposite-direction packet:

- no budget decrement
- no sparse-store lookup

Same-direction packet with TCP payload length 0:

- decrement budget using only the `Connection` marker
- if decrement reaches zero, erase retained sparse prefix and clear marker

Same-direction packet with non-zero TCP payload:

- probe sparse store exactly once
- verify TCP sequence continuity
- attempt exactly one two-segment SNI reconstruction
- erase sparse state regardless of success
- clear marker regardless of success

There is no third-segment wait.

## TCP Sequence Continuity

TCP sequence number must be propagated through transient import metadata only.

It must not be added to:

- `PacketRef`
- persisted `Connection` metadata
- capture index

Conceptual transient path:

```text
ParsedTcpSegment
    -> TcpFacts
    -> ImportDissectionFacts
    -> PacketImportMetadata
    -> TLS continuation logic
```

For a retained first segment, expected continuation must account for TCP
sequence-space rules.

Support SYN payload / TCP Fast Open correctly:

```text
expected_next_seq =
    first_seq
    + first_payload_length
    + (SYN ? 1 : 0)
```

Use uint32 sequence arithmetic so normal wraparound is preserved.

A retained first segment carrying FIN should be conservatively rejected.

The second segment must start exactly at `expected_next_seq`.

For gap, overlap, retransmission, or reordered segment:

- do not reconstruct
- erase pending state
- accept false negative

## Truncation Rules

Capture truncation is not TCP segmentation.

Use authoritative terminal transport bounds.

The first candidate may be retained only if the terminal TCP segment is fully
captured through its declared terminal payload end.

Do not rely only on whole-frame `captured_length == original_length`; the
relevant boundary is the authoritative terminal TCP payload.

If the second segment is capture-truncated such that the bounded two-segment
attempt cannot safely parse the required ClientHello bytes:

- fail
- erase pending state
- do not wait for another segment

## TLS Classification

Add a cheap internal ClientHello-prefix classifier that can distinguish at
least:

- `not_client_hello`
- `incomplete_client_hello`
- `complete_client_hello_without_sni`
- `client_hello_with_sni`
- `malformed_or_out_of_scope`

Preserve the current useful behavior where packet-local SNI extraction may
succeed before the entire declared ClientHello is captured, as long as the
required SNI extension bytes themselves are safely available.

The new classifier must not make existing packet-local SNI extraction
stricter.

Retained continuation is only for confirmed incomplete ClientHello data where
SNI is not yet available.

## Generic Hint Budget Interaction

The existing generic unresolved payload-hint budget and the TLS continuation
budget are separate.

Existing budget:

- generic unresolved payload attempts = 10

New budget:

- pending TLS same-direction packet lifetime = 3

They have different meanings and must not be merged.

The first retained ClientHello segment counts as a normal generic hint
attempt.

Once a TLS pending candidate exists, its one bounded continuation attempt is
allowed even if the generic hint budget subsequently becomes exhausted. This
exception does not reopen general hint scanning.

If the `Connection` obtains a definitive service hint while a TLS pending
candidate still exists, discard the pending candidate.

## Memory Bounds

Initial safety constants are implementation policy, not protocol limits:

- max pending candidates = 4096
- max total retained TLS prefix bytes = 8 MiB
- max retained prefix per candidate = 4096 bytes

Both count and byte bounds are useful:

- count bounds hash/container overhead
- total bytes bound retained payload memory
- per-entry cap prevents an unusually large captured TCP payload from becoming
  a large import-time retention object

If any bound prevents retention:

- do not insert sparse state
- do not set the `Connection` marker
- continue normal import

There is no eviction/LRU policy. False negatives are preferred over memory
growth.

## End-Of-Import Cleanup

`FlowHintService` sparse continuation state is import-scoped.

At successful, partial, failed, or cancelled import completion, retained TLS
prefix bytes must not survive the import processor lifetime.

`Connection` markers must also not be left claiming that sparse state exists
after the sparse store has been destroyed.

Preferred cleanup strategy:

- iterate only currently retained sparse candidates
- clear their corresponding `Connection` markers
- clear retained sparse state

Do not scan every `Connection` merely for cleanup. This is bounded by the
global pending-candidate limit.

Invariant after import finalization:

- no pending TLS sparse entries
- no `Connection` marker referring to destroyed pending state

## I/O / Performance Contract

Common-case behavior:

- No pending marker: no TLS sparse-store lookup and no new full-packet read
  caused by this feature.
- Pending marker + opposite direction: no sparse-store lookup and no new
  full-packet read.
- Pending marker + same direction + zero payload: marker/budget update only;
  sparse lookup only if expiry requires erase; no full-packet read.
- Pending marker + same direction + payload: one sparse lookup,
  materialize/read current packet bytes only if required, and one bounded
  continuation attempt.

This feature must preserve the current staged classic-PCAP import behavior.

## Existing Fixture Anchor

Primary regression fixture:

```text
tests/data/parsing/tls/tls_sni_in_second_segment_20.pcap
```

Its current documented shape is:

- packet 4 starts ClientHello, carries 1440 TCP payload bytes, and does not
  contain SNI bytes
- packet 5 is a contiguous continuation, carries 390 TCP payload bytes, and
  contains SNI
- expected SNI is `edge.microsoft.com`

Current product behavior:

- import detects TLS
- bounded two-segment continuation recovers `edge.microsoft.com` during open

Selected-flow reconstruction remains supported and unchanged.

`tls_1_3_split_client_hello_10.pcap` is not the primary target because its
first available ClientHello prefix already contains enough bytes for current
packet-local SNI extraction.

## Relationship To Selected-Flow Reconstruction

Open-time continuation is deliberately weaker.

Current behavior:

- simple two-segment contiguous ClientHello: open-time SNI can succeed
- more complex segmentation, retransmission, gaps, or longer reconstruction:
  open-time SNI may remain empty

Selected-flow bounded reconstruction remains the stronger on-demand fallback.

Do not merge the two architectures.

## Documentation Lifecycle

This RFC is current technical behavior. Broader release documentation,
showcase-derived CLI numeric examples, screenshots, and release artifacts are
updated separately during release preparation.
