# Smart Export v1

Status: implemented shared-backend feature design and engineering contract for
the original single-output Smart Export path.

This document defines the original Smart Export v1 packet-selection model and
the single-output-file execution contract. Later production extensions build on
these rules but do not replace them.

## Original v1 scope contract

The original v1 flow-selection scopes are:

- Current flow
- Selected flows
- Unselected flows
- All flows

Current production surfaces extend this family with additional selectors such
as filtered/not-filtered flow sets and an unrecognized-packets export mode.
Those later additions are outside the original v1 scope definition in this
document, but they reuse the same base/additional packet-retention semantics
where applicable.

## Base packet selection

Exactly one base rule is chosen:

- All packets
- First N packets
- First M original bytes

### Base rule semantics

- All packets: export all packets from the chosen flows.
- First N packets: export the first N packets of each chosen flow in that
  flow's packet order.
- First M original bytes:
  - accumulate original packet lengths in flow order
  - include packets until the threshold is reached
  - include the packet that crosses the threshold

## Additional packet retention

Optional rules:

- Include last packet
- Include every K-th packet after the base prefix

### Additional rule semantics

- Include last packet: include the last packet of the flow even if it was not
  already in the base prefix.
- Include every K-th packet after the base prefix:
  - applies only after the base prefix ends
  - adds sparse packets later in the flow
  - is evaluated relative to packet positions after the base prefix, not from
    the start of the flow
- If base mode is All packets, these additional options are disabled in the UI
  and are semantically redundant.

## Final packet-selection semantics

For each chosen flow, a packet is exported if it matches:

- the base rule
- OR Include last packet
- OR Include every K-th packet after the base prefix

A packet must never be exported more than once.

## Single-file architecture

The single-output-file path is intentionally capture-order preserving and
single-scan.

Implementation uses:

- a 1-byte-per-packet marker array / selection array
- one marking phase over ordered flow packet refs
- one final linear export pass over the source capture in original packet order

Do not:

- build a packet list with duplicates and sort/deduplicate later
- export in per-flow order
- use expensive post-hoc duplicate cleanup

## Output order

Exported packets must preserve original capture order.

## Byte semantics

- First M original bytes uses original packet length
- not captured length

## Source-byte boundary

Smart Export is source-capture-backed export.

- The exported output is materialized from source capture bytes.
- A standalone index is not enough by itself to produce export bytes.
- Index-backed export therefore still depends on an attached or otherwise
  available source capture.

## Progress and cancellation

The shared backend exposes progress/cancellation hooks for Smart Export, but
frontend behavior differs by surface.

- Qt currently runs Smart Export asynchronously and surfaces progress text,
  progress values, and cancellation.
- CLI surfaces progress text in command output.
- The Tauri spike currently exposes Smart Export through one-shot command
  paths with busy/status-level feedback rather than the same async
  progress/cancel flow used by Qt.

These surface differences do not change the shared packet-selection or
capture-order export contract.

## Out of scope for original v1

- protocol-specific rules
- time-based activity or liveness rules
- output-size preview
- advanced presets
