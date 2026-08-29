# PcapFlowLab Agent Guide

PcapFlowLab is a flow-first PCAP/PCAPNG analyzer designed to stay practical on
large captures. The backend/session model is shared across Qt, Tauri, and CLI
surfaces.

## Start Here

Before making non-trivial changes, inspect only the current contracts relevant
to the subsystem you are touching.

Primary technical documentation entrypoint:

- `docs/README.md`

Authority routing:

- `docs/**` -> current technical contracts and engineering references
- `user_docs/**` -> current end-user documentation
- `docs/history/**` -> historical rationale, not current behavioral authority

When current documentation, implementation, and tests appear inconsistent,
identify the inconsistency explicitly instead of silently assuming historical
documentation is authoritative.

## Documentation Map

### General architecture and current state

- `docs/README.md` -> technical documentation entrypoint
- `docs/current-state.md` -> current product behavior, scope boundaries, and
  major workflows
- `docs/architecture.md` -> runtime architecture, persistence boundaries, and
  source-byte ownership
- `docs/decisions.md` -> stable architectural decisions the current
  implementation follows

### Capture import, index, and retained metadata

- `docs/architecture.md` -> import/open pipeline and persistence boundaries
- `docs/features/index-v15-container-rfc.md` -> current stable index/container
  compatibility contract
- `docs/features/flow-aggregate-metadata-rfc.md` -> retained flow metadata and
  compact persistent packet metadata foundation
- `docs/dissection-import-validation.md` -> import-validation and parity-tool
  behavior for diagnostics and cutover work

### Flow identity and Protocol Path

- `docs/protocols/protocol_path_flow_identity.md` -> canonical flow grouping,
  protocol-path identity, and normalization behavior

### Protocol parsing and presentation support

- `docs/protocols/protocol_support.md` -> authoritative current protocol
  capability reference across import, grouping, packet details, stream, and
  fixtures

### Selected packet, selected flow, Stream, and reassembly

- `docs/selected-flow-contract.md` -> selected-packet and selected-flow
  inspection contract
- `docs/stream_architecture.md` -> Stream responsibilities and selected-flow
  materialization rules
- `docs/reassembly-rfc.md` -> bounded reconstruction and reassembly reference
- `docs/selected-flow-packet-cache-rfc.md` -> selected-flow byte-cache
  behavior and limits

### Analysis

- `docs/analysis-tab.md` -> current selected-flow Analysis technical contract

### Statistics and shared desktop presentation

- `docs/ui/presentation_contract.md` -> canonical shared desktop presentation
  semantics
- `docs/current-state.md` -> current Statistics scope and lazy-loading
  behavior overview
- `user_docs/ui/statistics.md` -> end-user Statistics workflow wording

There is no separate dedicated current Statistics technical contract beyond the
shared presentation contract and current-state overview.

### Frontend/session DTO and Qt/Tauri boundaries

- `docs/ui/presentation_contract.md` -> canonical shared presentation contract
- `docs/ui/frontend_dto_mapping.md` -> engineering DTO mapping and audit
  reference, not the product contract by itself
- `experimental/tauri-ui-spike/README.md` -> current Tauri implementation
  status and local frontend notes

### Advanced Flow Filter

- `docs/features/advanced-flow-filter-rfc.md` -> backend text format,
  compiler, evaluator, and CLI contract
- `docs/features/advanced-flow-filter-ui-rfc.md` -> UI editor, document-state,
  file-workflow, and shared Qt/Tauri interaction contract

### Export and Smart Export

- `docs/features/smart-export-v1.md` -> shared Smart Export packet-selection
  and single-output contract
- `docs/features/smart-export-per-flow-v1.md` -> per-flow Smart Export output
  contract
- `docs/cli/commands/export-flows.md` -> CLI-specific export command behavior

### CLI

- `docs/cli/README.md` -> CLI technical documentation entrypoint
- `docs/cli/architecture.md` -> CLI architecture and responsibility split
- `docs/cli/commands/` -> command-specific technical contracts

### Performance and scalability

- `docs/large-capture-performance-guidelines.md` -> hot-path, bounded-work,
  and large-capture guidance
- `docs/selected-flow-packet-cache-rfc.md` -> selected-flow caching and byte
  materialization boundaries

### End-user documentation

- `user_docs/README.md` -> entrypoint for user-visible workflows, terminology,
  settings, and usage documentation

Technical contracts under `docs/**` remain the primary engineering authority.

### Historical material

- `docs/history/**` -> preserved rationale, audits, and superseded design
  context; not current authority

## Stable Architectural Invariants

### Flow-first model

Canonical user-visible flows are bidirectional connections.

`Endpoint A` / `Endpoint B` orientation is a presentation orientation derived
from the first observed packet. Do not infer client/server semantics from A/B
unless an explicit subsystem does so separately.

`A -> B` therefore means the first-observed direction and `B -> A` its
reverse.

### Keep persisted per-packet state lightweight

PcapFlowLab targets large captures.

Avoid adding fields to `PacketRef` or other retained per-packet structures
unless the value has a demonstrated persistent or hot-path need.

Prefer deriving presentation-only data lazily from authoritative source bytes
or existing aggregates.

Changes that add even a few bytes per packet deserve explicit memory-cost
consideration.

### Preserve persistence and source-byte boundaries

Indexes persist reusable metadata and session state, not raw packet bytes,
reassembly buffers, Stream artifacts, or selected-flow ephemeral caches.

Byte-backed features require authoritative source bytes. Do not accidentally
make metadata-only index usage depend on source packet reads.

Index format changes must be deliberate and justified by a real persistence
requirement.

### Selected-flow work must remain bounded

Selected-packet and selected-flow inspection is lazy and on demand.

Stream construction, reassembly, protocol enrichment, and byte materialization
must respect selected-flow packet or item windows and byte budgets.

Do not replace bounded work with implicit full-flow scans or unbounded
reassembly. Do not introduce global open-time stream reconstruction for a
feature that can remain selected-flow and on demand.

### Protect large-capture hot paths

Be suspicious of:

- per-packet heap allocations
- repeated protocol-path normalization or interning
- repeated materialization of packet bytes
- accidental `O(flow-size)` work in metadata-backed UI or filter operations
- whole-capture rescans for presentation-only features
- redundant DTO, string, hex, or JSON materialization

Prefer lightweight descriptors, cached lookup, and on-demand materialization
where ownership and lifetime allow it.

### Shared backend semantics are authoritative

Qt, Tauri, and CLI may have different layouts and interactions, but they
should not silently implement different protocol, filter, session, or export
semantics.

Prefer shared C++ backend/session/frontend contracts. Do not create
independent JS or Rust parsers or evaluators for semantics already owned by
C++.

In particular, Advanced Flow Filter parser, formatter, structured-document
semantics, compiler, and evaluator are authoritative C++ behavior.

### Validate at the nearest public boundary

Validation should happen at the boundary that can report the most useful
error.

Examples:

- structured-editor decode should report field-specific invalid input
- text parser should report grammar and value errors
- compiler or evaluator should remain defensive against invalid programmatic
  specs

Do not remove deeper defensive validation merely because an earlier layer now
rejects the same invalid state.

### Parser, formatter, DTO, tests, and docs must agree

For persisted or user-editable text contracts:

- parser grammar
- canonical formatter output
- structured editor representation
- examples and RFC grammar
- tests

must describe the same keys, quoting rules, units, tokens, and
inclusive/range semantics.

When modifying one side, explicitly inspect the others for drift.

### Preserve frontend parity without forcing identical layout

Qt is the primary desktop semantic and UX reference.

Tauri is experimental, but shared features should preserve functional parity
unless a gap is explicitly intentional and documented.

Layout and visual implementation may differ. Backend semantics should not.

### Preserve explicit empty vs absent semantics

Where bridges or ABIs distinguish an omitted scope from an explicitly empty
scope, preserve that distinction across C++, FFI, Rust, and JavaScript.

Do not collapse semantically different null and empty states for convenience.

## Tests And Documentation

For behavior changes, inspect existing unit, UI, and CLI coverage before
inventing a parallel test approach. Prefer focused boundary and regression
tests.

Common boundary cases include:

- `min == max`
- reversed ranges
- empty or zero reverse direction
- malformed or truncated input
- raw-capture vs index-backed behavior
- enabled or disabled state retention
- pagination or bounded-window behavior
- Qt and Tauri structured-document parity

Do not claim a build, test, or application run occurred unless it actually
occurred.

Keep current documentation synchronized with implemented contracts. Do not
rewrite historical documents merely to make them look current.
