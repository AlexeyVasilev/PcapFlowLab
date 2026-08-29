---
name: code-review
description: Review PcapFlowLab pull requests and code changes for correctness, architecture-contract violations, large-capture performance regressions, persistence/index issues, frontend/backend semantic drift, boundary-validation gaps, missing tests, and documentation drift. Use for code review of PcapFlowLab changes.
---

# PcapFlowLab Code Review

Review the change against `AGENTS.md` first.

Read only the current contracts relevant to the changed subsystem. Start from
`docs/README.md`.

Focus on actionable correctness, architecture, performance, compatibility, and
test or documentation findings. Do not spend review budget on subjective style
nits unless they hide a real defect.

## Review Procedure

### 1. Establish the authoritative path

Identify:

- where the canonical semantics live
- whether the change touches import, persisted metadata, selected-packet,
  selected-flow, presentation, export, or filter paths
- which current contract documents apply

Watch for frontend code becoming a second implementation of backend semantics.

### 2. Check validation boundaries

For every newly editable, parsed, or bridged field or DTO, verify that the
closest boundary capable of producing a precise error handles:

- malformed input
- overflow
- reversed ranges
- inclusive boundaries
- empty values
- unknown enum or stable IDs
- mutually dependent fields

Then verify deeper compiler or runtime layers remain defensive.

### 3. Check parser, formatter, structured DTO, and docs consistency

For user-editable or persisted text contracts, compare:

- parser keys and accepted syntax
- formatter keys and canonical syntax
- quoting and escaping
- units
- enum tokens
- version declarations
- structured DTO mapping
- RFC and user documentation examples
- round-trip tests

Flag any documented syntax that would not actually parse or round-trip.

### 4. Check large-capture cost

Look specifically for:

- new retained bytes per packet
- new `PacketRef` fields
- heap allocations in packet or import hot paths
- repeated string, hex, or byte materialization
- full-flow scans introduced into metadata-backed operations
- whole-capture rescans
- unbounded reassembly
- repeated protocol-path normalization or interning
- accidental copying of large packet or stream collections

For selected-flow work, confirm existing windows and budgets remain
authoritative.

### 5. Check persistence and source-byte boundaries

If retained or indexed state changes:

- verify a real persistence requirement exists
- verify index compatibility consequences are handled intentionally
- verify index-only sessions remain valid where expected

Do not allow raw bytes, reassembly state, or selected-flow ephemeral artifacts
to leak into the persisted model without explicit architectural justification.

### 6. Check flow orientation and directionality

Remember:

- canonical flows are bidirectional
- `Endpoint A/B` orientation comes from the first observed packet
- `A -> B` is first-observed direction
- `B -> A` is reverse
- this is not client/server inference

Check zero reverse-direction cases and exact distribution or range boundaries.

### 7. Check Qt, Tauri, and CLI semantic parity

When a shared feature changes, inspect whether all applicable surfaces still
use the same backend semantics.

Pay special attention to:

- C++ frontend bridge
- Rust DTO and FFI ownership
- C string or string-owner lifetimes
- JavaScript rendering or editing
- null vs explicit-empty candidate scopes
- rule counting and enabled or disabled state
- user-visible labels vs canonical persisted tokens

Do not require identical layouts. Do require equivalent semantics unless a gap
is explicitly intentional.

### 8. Check tests

Expect focused tests for the failure mode introduced by the change.

Prefer tests at the boundary where the bug would surface. Look for:

- `min == max`
- `min > max`
- zero or missing reverse direction
- overflow
- malformed or truncated data
- enabled or disabled retention
- raw/index round-trip
- parser/formatter round-trip
- structured-document error field or group IDs
- bounded-window behavior

Do not accept a test that only exercises a later fallback when an earlier
public boundary is supposed to reject the input.

### 9. Check documentation drift

If syntax, UI terminology, semantics, or persistence behavior changes, compare
the relevant current docs.

Literal examples must match the real grammar exactly. Do not report historical
docs under `docs/history/**` merely for preserving old behavior or design
descriptions.

### 10. Report findings

Report only concrete findings.

For each finding:

- identify the affected file or location
- explain the observable correctness, performance, or contract impact
- explain the violated invariant or mismatched contract
- suggest the smallest appropriate correction

Distinguish blockers and correctness issues from optional improvements. Avoid
broad refactoring recommendations unrelated to the changed code.

If no actionable issue is found, say so rather than inventing speculative
comments.
