# Protocol Recognition Stats RFC

## Purpose

This RFC defines a narrow first step for protocol recognition statistics in the Statistics tab.

The goal is to expose capture-wide recognition quality using already available flow-level metadata and hints. This is a summary/aggregation view, not a new deep-analysis engine.

Initial scope is QUIC-only.

## Initial QUIC scope

The first implementation should report:

- total QUIC flows
- QUIC flows with SNI
- QUIC flows without SNI
- QUIC version distribution:
  - v1
  - draft-29
  - v2
  - unknown

For this RFC, a QUIC flow is any connection with `protocol_hint == "quic"`. Flows where QUIC parsing was only partially attempted but not classified as QUIC are not included in QUIC totals.

`QUIC flows with SNI` means `service_hint` was successfully extracted from QUIC Initial data.

`QUIC flows without SNI` means a QUIC flow where no SNI is available, including both cases where parsing was attempted but no SNI was extracted and cases where parsing was not possible (for example: incomplete data, decryption failure, unsupported version).

Reason-level breakdown for `without SNI` is out of scope for this step; all such cases stay in one bucket.

QUIC version is taken from the parsed QUIC Initial header when available. If parsing fails or version is not available, the flow is counted in `unknown`. Version inference beyond parser-provided values is out of scope.

Counts are primary values. Percentages are derived display values and should be shown together where useful (for example: `80% (800 connections)`).

Unknown buckets are required. Unsupported or unknown QUIC versions must not be dropped from totals.

## Architectural rule

Statistics must be derived from already available flow-level metadata and hints.

- no additional global parser pass just to compute statistics
- no reassembly execution just for statistics
- no new expensive deep analysis added to open/import

Statistics may be computed lazily on demand or cached after first computation, but either approach must not trigger additional parsing work.

This RFC does not change fast-path import behavior or deep-path bounds.

## UI shape (first step)

UI stays summary-oriented and simple:

- capture-wide counts first
- percentages as derived values
- explicit `with SNI` and `without SNI` buckets
- explicit QUIC version buckets including `unknown`

Statistics reflect final available flow metadata for the session and must not depend on whether SNI or version metadata came from deep import or from fast-mode on-demand enrichment.

## Determinism

Given the same capture and the same parser version, statistics should be deterministic.

Statistics must not depend on UI interaction order (for example, which flows were selected first).

## Non-goals (first step)

- no TLS or HTTP recognition statistics yet
- no drill-down or filter integration
- no per-reason parser-failure statistics
- no protocol confidence/score system
- no new persistence/index fields
- no global recomputation framework

## Boundaries and consistency

This RFC is consistent with current architecture:

- fast path remains unchanged
- deep path remains bounded
- statistics are aggregation over existing state
- no new protocol parsing work is introduced for this step

## Possible later extensions (out of scope now)

- TLS recognition statistics
- HTTP recognition statistics
- drill-down and filter integration
