# Decisions

This document records stable architectural decisions for Pcap Flow Lab.

## Core processing

- Capture open/import stays packet-oriented and bounded.
- No global Stream or reassembly work runs during capture open.
- More expensive selected-flow work is deferred until explicitly requested.

## Persistence

- Analysis indexes persist reusable metadata, not raw packet bytes.
- Stream artifacts and reassembly buffers are not stored in indexes.
- Index compatibility is exact-version, not backward-compatible by default.

## Flow identity

- Canonical flow identity is protocol-path-aware, not endpoint-tuple-only.
- User-facing `Endpoint A` / `Endpoint B` orientation is first-observed, not
  inferred client/server truth.
- Raw-import grouping normalization settings affect flow identity only at import
  time and are not reapplied on later index load.

## Selected-packet and selected-flow work

- Selected-packet byte inspection is lazy and source-byte-backed.
- Selected-flow analysis is on-demand, bounded, and ephemeral.
- Stream reconstruction is heuristic and bounded; it is not full TCP-correct
  recovery.
- Stream Item `Item Data` is shown only when authoritative item-owned bytes or
  explicit retained provenance exist.

## Parsing philosophy

- Conservative parsing is preferred over speculative classification.
- Malformed or truncated packets may still surface partial safe facts, but
  unsupported deeper structure is not fabricated.
- QUIC and other richer protocol inspections may be useful while still
  remaining explicitly bounded and incomplete.

## Shared application architecture

- Qt, Tauri, and CLI share backend/session semantics instead of duplicating
  core parsing and grouping logic independently.
- Frontends own layout, interaction, and rendering; shared backend/session code
  owns canonical parsing, grouping, statistics, and byte-backed presentation
  semantics where those contracts exist.

## Scalability defaults

- Large interactive lists prefer virtualization and bounded incremental
  materialization before pagination is introduced.
