# QUIC Initial RFC

## Status

Status: implemented design RFC and historical record of the QUIC Initial rollout.

This document remains useful as the design history for bounded QUIC Initial
inspection, but the current product contract is defined by the canonical
architecture and protocol-support documents.

Current reader guidance:

- treat this RFC as the historical design for how bounded QUIC Initial support
  was introduced
- use [docs/protocols/protocol_support.md](docs/protocols/protocol_support.md)
  for current support scope
- use [docs/stream_architecture.md](docs/stream_architecture.md) and
  [docs/selected-flow-contract.md](docs/selected-flow-contract.md) for current
  selected-flow and selected-packet presentation rules

## Purpose

This RFC defines a narrow first step for QUIC parsing.

The immediate goal is not general QUIC support. The first useful outcome is limited to:

- detecting client QUIC Initial packets
- extracting SNI from the embedded TLS ClientHello when enough crypto data is available
- using that result conservatively for `service_hint` and related UI visibility

The design was phased deliberately.

- Phase 1: implemented as the first conservative client Initial SNI extraction
  step
- Phase 2: implemented in bounded selected-flow form
- Phase 3: partially implemented and otherwise superseded by the current
  selected-packet `Summary` / `Bytes` and selected-flow `Stream` /
  `Stream Item Details` surfaces

## Scope

Originally supported in Phase 1:

- client -> server direction only
- QUIC long-header Initial packets only
- server Initial packets are ignored in Phase 1
- bounded single-packet parsing
- multiple CRYPTO frames inside one Initial packet
- CRYPTO assembly by offset within that one packet
- TLS ClientHello parsing only after assembled crypto bytes are available
- SNI extraction only when the assembled ClientHello is complete enough

Not supported as part of this RFC's Initial-only scope:

- general QUIC stream parsing
- broader server-side parsing
- 0-RTT, Handshake, Retry, or short-header traffic analysis
- full QUIC session reconstruction
- packet-loss or reordering repair
- transport-correct recovery across arbitrary packet boundaries

## Phased plan

### Phase 1

Phase 1 is intentionally small.

- Detect and parse client QUIC Initial packets.
- Collect all CRYPTO frames present in that one packet.
- Assemble CRYPTO payload by crypto-stream offset within that packet.
- Pass only the assembled crypto byte stream to TLS ClientHello parsing.
- Extract SNI when the ClientHello is complete enough.

This phase is useful even without multi-packet support because some captures place enough ClientHello crypto data in a single Initial packet.

#### Decryption scope (Phase 1)

Phase 1 decryption support is intentionally narrow.

- Only Initial packet protection removal is supported.
- Only Initial key derivation is in scope.
- No Handshake keys, 0-RTT keys, or key updates are supported.

### Phase 2

Phase 2 extends the same correctness rule to a bounded packet set.

- Collect CRYPTO frames from the first `N` client Initial packets in one direction.
- Process packets strictly in capture order (`packet_index` order).
- Do not reorder by QUIC packet number.
- Do not attempt to repair loss or reordering.
- Assemble the crypto stream by offset across that bounded set.
- Parse TLS ClientHello from the assembled crypto bytes.
- Extract SNI only if enough ordered crypto data is available.
- Keep explicit bounded limits: max packets, max crypto bytes, and CRYPTO
  frames. In the current implementation these bounds are conservative and
  explicit: at most three Initial packets, sixteen KiB of CRYPTO bytes, and
  sixty-four CRYPTO frames.

This remains bounded work and stays consistent with the existing packet-oriented architecture. It is not general QUIC reassembly and it does not imply broader QUIC session support.

### Phase 3

Phase 3 was optional polish only.

- UI/service-hint presentation improvements for successfully parsed QUIC
  Initials
- possible Stream labeling improvements for selected-flow analysis

The current product implements the important presentation outcome of this phase:

- selected-packet `Summary` can expose QUIC shell, frame-presence, and bounded
  TLS handshake detail for contributing Initial packets
- selected-packet `Bytes` can expose bounded authoritative QUIC Initial and
  CRYPTO/TLS-derived byte views
- selected-flow `Stream` and `Stream Item Details` can expose bounded QUIC
  semantic rows such as `QUIC Initial: CRYPTO` and `QUIC Initial: ACK`

Phase 3 did not change the core bounded parsing rules.

## Critical correctness rule

QUIC Initial parsing must not pass only the first CRYPTO frame directly to TLS parsing.

All CRYPTO frames available in the current parsing scope must first be assembled by crypto-stream offset.

- In Phase 1, that scope is one client Initial packet.
- In Phase 2, that scope is the bounded set of first client Initial packets.

TLS ClientHello parsing happens only on the assembled crypto byte stream.

This rule is required to avoid false negatives and malformed partial TLS parsing when a ClientHello is split across multiple CRYPTO frames.

## Where parsing is allowed to run

### Deep open

A bounded single-packet QUIC Initial parser may run during deep open when that work stays aligned with existing bounded enrichment policy.

- Intended output is a conservative `service_hint` when SNI extraction succeeds.
- No broader QUIC session state is implied.

In the current product this remains intentionally narrow import-time enrichment.
The richer packet-summary, packet-bytes, and selected-flow QUIC surfaces are
selected-packet or selected-flow operations rather than global QUIC parsing
during capture open.

### Fast-opened capture

The same parser may run on demand for the currently selected QUIC flow.

- This path is initially allowed to remain ephemeral and UI-facing.
- It must stay scoped to selected-flow analysis.
- It must not introduce global expensive QUIC work during fast open.

In the current product, bounded selected-flow context may contribute
authoritative reconstructed or derived bytes for explicitly supported Initial /
CRYPTO / TLS views, but this does not imply unbounded flow-wide reassembly or
general QUIC session reconstruction.

## Conservative outcomes

The parser should return conservative outcomes rather than guessing.

Expected outcomes include:

- malformed QUIC packet
- unsupported version
- decryption failure
- incomplete crypto data
- incomplete TLS ClientHello

In all of these cases, the parser must fall back conservatively with no SNI result.

- keep `protocol_hint` as `quic` if it is already known
- extracted SNI may be used for `service_hint` when parsing succeeds
- `service_hint` must not overwrite higher-confidence protocol hints
- do not invent `service_hint`
- do not guess SNI or broader protocol meaning if parsing is incomplete

## Persistence and architectural boundaries

This RFC does not change the current architectural boundaries.

- fast path remains packet-oriented
- deep enrichment remains bounded
- on-demand flow-local analysis remains ephemeral
- no QUIC stream artifacts are persisted
- no temporary crypto assembly artifacts are persisted
- no global QUIC analysis is added to fast open
- this RFC does not introduce general QUIC parsing

Current verified decryption boundary:

- QUIC Initial decryption is supported conservatively for the implemented
  selected-packet and selected-flow presentation paths
- supported Initial-version handling includes QUIC v1, QUIC v2, and draft-29
- no Handshake-key decryption, 0-RTT-key decryption, or general protected
  application-data decryption is implied by this RFC

## Reuse of prior art

The older project's single-packet QUIC Initial parser and unit tests are useful reference material.

Recommended reuse targets:

- single-packet Initial fixtures
- expected SNI extraction results
- malformed or incomplete test cases

That prior code should be treated as reference, not as a drop-in component.

Any reused logic should be adapted to the current project's boundaries, naming, error handling, and test style.

## Implementation guardrails

The first implementation step should stay intentionally narrow.

- Parse only client Initial packets.
- Assemble all CRYPTO frames in scope by offset before TLS parsing.
- Prefer false negatives over false positives.
- Do not add broader QUIC semantics as part of SNI extraction.
- Keep deep-open work bounded and selected-flow on-demand work ephemeral.

This RFC is a starting point for useful QUIC visibility, not a commitment to full QUIC analysis.
