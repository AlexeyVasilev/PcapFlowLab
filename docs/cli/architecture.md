# CLI Architecture

This document describes the current Pcap Flow Lab CLI architecture and the
shared runtime boundaries it relies on.

## Public commands

The CLI exposes five public commands:

- `summary`
- `flows`
- `export-flows`
- `flow-info`
- `packet-info`

The dispatcher also accepts these compatibility aliases:

- `flow` -> `flows`
- `export-flow` -> `export-flows`
- `flows-info` -> `flow-info`
- `packets-info` -> `packet-info`

Global help documents only the canonical command names.

## Input dispatch

The top-level CLI accepts either:

- a positional input path; or
- `--input <path>`

These forms are mutually exclusive.

The dispatcher auto-detects whether the input path is:

- a raw capture; or
- an index.

Top-level behavior is intentionally simple:

- no-argument invocation prints global help and exits non-zero;
- `-h` and `--help` print global help and exit zero;
- command-specific help is routed through the selected command parser.

## Shared processing model

The CLI does not implement a separate packet parsing or grouping stack.

It reuses shared C++ backend/session/frontend presentation layers for:

- capture opening;
- flow grouping and indexing;
- flow querying;
- statistics presentation DTOs;
- packet summary generation;
- packet byte materialization;
- stream item data materialization where exposed through shared services.

## Layer boundaries

### `core/`

Owns foundational packet/capture/index services and low-level parsing.

### `app/session/`

Owns capture-session orchestration, flow state, packet/session presentation,
querying, bounded selected-flow analysis, statistics, and byte-backed
inspection/export helpers.

### `app/frontend/`

Owns shared adapter/bridge-oriented presentation contracts used directly by
Tauri and by CLI commands where that boundary is appropriate.

Qt does not route all behavior through `FrontendSessionAdapter`; its
`MainController` also calls `CaptureSession` and session-level services
directly. Even so, Qt, Tauri, and CLI still share the same backend/session
semantics rather than implementing independent protocol-processing pipelines.

## Frontend/session presentation path

The CLI uses command parsers plus shared runtime helpers in `src/cli/**`.
Command execution commonly opens input through shared helpers, then consumes
shared session/frontend presentation APIs to render terminal output.

That shared presentation path is not identical across all application surfaces:

- Tauri uses the adapter/bridge boundary;
- CLI commands also use `FrontendSessionAdapter` where appropriate;
- Qt combines shared presentation helpers with more direct session access.

The architectural constraint is shared semantics, not identical call graphs.

## Settings JSON boundary

The CLI settings-file parser is intentionally narrow. It currently accepts only:

- `ignore_vlan_and_mpls_layers_when_grouping_flows`
- `ignore_gtpu_teids_when_grouping_inner_flows`
- `validate_selected_packet_checksums`

Unknown settings fields are rejected.

This parser boundary is stricter than the full in-process frontend settings DTO.

## Source-backed versus index-backed work

Some CLI operations can run entirely from an index. Others require source packet
bytes.

Index-backed metadata/reporting operations may succeed without source capture
bytes. Byte-backed inspection/export operations require authoritative source
capture access and may accept `--source-capture <path>` when opening an index.

## Selected-packet lazy inspection

Selected-packet inspection is lazy and selected-packet-oriented.

It starts from:

- the selected packet;
- that packet's source-backed captured bytes when available.

Normal packet facts remain selected-packet-oriented. Where an explicitly
supported derived byte view requires it, bounded selected-flow context may
contribute authoritative reconstructed or derived bytes. This does not imply
global reassembly, unbounded contextual reading, or whole-capture byte
materialization.

## Selected-flow bounded ephemeral analysis

Selected-flow analysis paths are bounded and ephemeral. They support
selected-flow querying and presentation such as:

- analysis-pane calculations;
- bounded packet/stream projections;
- selected packet or stream inspection context where required.

This bounded analysis path is distinct from normal flow export. Flow export and
Smart Export remain byte-backed/source-capture-dependent, but they are not
conceptually limited to the currently materialized selected-flow window.

## Export boundaries

CLI export commands write derived files through explicit output arguments. The
runtime performs conservative preflight checks, including path validation and
overwrite protection unless `--force` is supplied.

## Numbering

All user-facing flow numbers and packet numbers are 1-based. Internal runtime
indices remain zero-based where convenient, but the public CLI contract is
one-based.
