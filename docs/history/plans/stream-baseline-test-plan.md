# Stream Baseline Fixture Test Plan

## Status

Status: implemented historical Stream fixture test plan.

This document recorded the baseline strategy used while selected-flow Stream
behavior was being stabilized. Many of the proposed fixture-backed tests and
protocol-aware behaviors have since landed, so this file should no longer be
read as an active "tests to add first" plan.

Current authoritative behavior belongs to:

- `docs/stream_architecture.md`
- `docs/selected-flow-contract.md`
- committed fixture expectation files and current regression tests

## Historical purpose

The purpose of this plan was to introduce a narrow, fixture-backed Stream
baseline before larger Stream materialization changes continued.

That testing strategy remains valid:

- prefer repository fixtures where they safely cover real behavior;
- use narrow semantic assertions rather than brittle full-text snapshots;
- distinguish complete, partial, bounded, and unavailable behavior honestly;
- verify ownership/provenance where byte-backed details are part of the
  contract;
- complement synthetic unit tests with fixture-backed captures rather than
  replacing them.

## Historical plan themes that still matter

The most useful lasting principles from the plan are:

- assert key labels and semantic categories rather than incidental formatting;
- test protocol-aware behavior conservatively;
- check fallback behavior by category rather than snapshotting whole panes;
- keep fixture baselines small and understandable where possible;
- use exact fixture contracts where protocol ownership or mixed semantics are
  easy to regress.

## What changed after this plan

Several claims in the original working plan are now historical and must not be
treated as current behavior:

- DNS and mDNS no longer belong to an old fast-vs-deep split where fast stays
  generic UDP and only deep becomes protocol-aware;
- selected-flow Stream now has packet-local structured DNS and mDNS rows where
  the bytes support reliable classification;
- QUIC selected-flow Stream no longer needs to remain generic `UDP Payload`;
- current QUIC rows include bounded protocol-aware labels such as
  `QUIC Initial: CRYPTO`, `QUIC Initial: ACK`, `0-RTT`, `Handshake`, and
  `Protected payload`;
- Stream Item Details no longer exposes a visible Protocol tab;
- current Stream Item Details surface is `Summary` plus `Item Data`.

## Current implemented baseline areas

The historical baseline idea has effectively been implemented across the
current regression suite.

Current repository-backed and synthetic coverage now includes, at minimum:

- generic TCP and UDP fallback behavior;
- HTTP request/response/multi-message/partial handling;
- TLS single-packet and bounded reassembly cases;
- DNS and mDNS packet-local structured Stream behavior;
- QUIC protocol-aware selected-flow semantics and conservative fallback;
- selected-flow bounded `Load more` behavior;
- Stream Item `Data` ownership and availability behavior.

The exact current regression contract belongs in:

- current fixture READMEs;
- `tests/fixtures/**` expectation files;
- unit and UI test suites.

This file should not be expanded into the canonical Stream reference.

## Current role

This document is still worth keeping because it captures the assertion
philosophy behind the Stream stabilization work.

It is not the place to restate every current protocol-specific Stream rule.

Those current protocol rules belong in:

- `docs/stream_architecture.md`
- `docs/selected-flow-contract.md`
- `docs/protocols/protocol_support.md`

## Recommended future location

This file is a strong candidate for later relocation to:

- `docs/history/testing/`
