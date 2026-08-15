# Protocol Recognition Stats RFC

## Status

Status: implemented design RFC / historical feature design.

This RFC introduced the recognition-quality statistics concept as a bounded
aggregation over metadata already produced by normal capture import and flow
hinting. The current product has moved beyond the original QUIC-only first
step, so this document should be read as the implemented design history rather
than as the authoritative current contract.

Current authoritative behavior belongs to:

- `docs/current-state.md`
- `docs/architecture.md`
- `docs/protocols/protocol_support.md`
- current production implementation and UI

## Original purpose

The original purpose of this RFC was to define a narrow first step for protocol
recognition statistics in the Statistics workspace.

The architectural rule introduced here remains correct:

- aggregate existing flow/session metadata;
- do not add a new global protocol-parsing pass merely for statistics;
- do not trigger reassembly only to populate capture-wide recognition stats;
- keep Statistics lazy and cacheable where useful.

That rule still matches current production behavior.

## What was originally proposed

The original first-step scope was QUIC-only.

The first-step QUIC proposal recorded:

- total QUIC flows;
- QUIC flows with SNI;
- QUIC flows without SNI;
- QUIC version distribution:
  - v1
  - draft-29
  - v2
  - unknown

That first-step wording is historical. It is no longer the full current scope.

## Current verified implementation facts

Current production Statistics exposes a lazy `QUIC and TLS` section rather than
the original QUIC-only section.

Verified current shared-backend statistics include:

- QUIC totals;
- QUIC with-SNI / without-SNI counts;
- QUIC version counts for:
  - v1
  - draft-29
  - v2
  - unknown
- TLS totals;
- TLS with-SNI / without-SNI counts;
- TLS version counts for:
  - TLS 1.2
  - TLS 1.3
  - unknown

Verified current frontend exposure includes:

- shared backend/session summary fields for QUIC and TLS recognition stats;
- bridge/frontend DTO exposure for both QUIC and TLS recognition summaries;
- Qt Statistics rendering in the `QUIC and TLS` optional section;
- lazy request/caching behavior consistent with the rest of the optional
  Statistics sections.

## Current architectural boundary

The current recognition-statistics feature is still an aggregation view, not a
separate deep-analysis engine.

It remains bounded by existing metadata already produced by normal import and
hinting flows.

Current implementation still does not imply:

- a new global recognition-only parser pass;
- capture-wide reassembly initiated solely for Statistics;
- a new persistence layer dedicated to recognition statistics.

## Historical non-goals

The following were original first-step non-goals:

- TLS recognition statistics;
- drill-down or filter integration;
- per-reason parser-failure statistics;
- protocol confidence/score systems;
- new persistence/index fields.

These should now be read historically.

Current verified status:

- TLS recognition statistics were added later and are now implemented.
- There is still no dedicated drill-down/filter workflow specific to the QUIC
  and TLS recognition section; do not confuse Protocol Path drill-down with
  recognition-statistics drill-down.
- Per-reason recognition-failure breakdown remains outside the current shared
  Statistics contract.

## Role going forward

This file should remain as the historical design record for how recognition
statistics were introduced and bounded.

It is a strong candidate for later relocation to:

- `docs/history/rfc/`
