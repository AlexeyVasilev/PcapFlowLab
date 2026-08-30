# Pcap Flow Lab Technical Documentation

This is the technical/developer documentation entrypoint for Pcap Flow Lab.

### Current contracts

Current contracts define implemented architecture, behavior, UI semantics,
protocol support, and command behavior. Together with current implementation
and tests where appropriate, they are the authoritative source for current
Pcap Flow Lab behavior.

### Current references and operational docs

Current references cover engineering mappings, tooling, performance
guidelines, export contracts, release/process documentation, and the active
backlog. They are current and useful, but not all of them are primary
product/runtime contracts.

### Historical documentation

[`docs/history/**`](history/README.md) preserves implemented RFCs, design
evolution, audits, investigations, and superseded plans. Historical documents
are retained for rationale, but they are not authoritative for current
behavior.

End-user documentation lives separately under `user_docs/`.

## Start Here

- [Current State](current-state.md)
  Current product behavior, scope boundaries, and major workflows.
- [Architecture](architecture.md)
  Current architecture, persistence boundaries, and runtime processing paths.
- [Stable Decisions](decisions.md)
  Stable architectural decisions that the current implementation follows.

## Protocols And Flow Identity

- [Protocol Support](protocols/protocol_support.md)
  Detailed current protocol capability reference.
- [Protocol Path Flow Identity](protocols/protocol_path_flow_identity.md)
  Current path-aware normalized flow-identity contract.

## Selected Packet, Flow, Stream, And Analysis

- [Selected Flow Contract](selected-flow-contract.md)
  Current selected-packet and selected-flow inspection contract.
- [Stream Architecture](stream_architecture.md)
  Current bounded selected-flow Stream model and materialization rules.
- [Reassembly Reference](reassembly-rfc.md)
  Current bounded reassembly engineering reference despite the filename.
- [Analysis](analysis-tab.md)
  Current selected-flow Analysis contract and subsystem boundaries.

Selected packet inspection is lazy and source-backed. Selected-flow work is
bounded and on demand. Stream and Analysis are separate subsystems with
different responsibilities.

## UI

- [Presentation Contract](ui/presentation_contract.md)
  Canonical shared UI presentation semantics contract.
- [Frontend DTO Mapping](ui/frontend_dto_mapping.md)
  Current engineering mapping/reference; useful, but not the canonical product
  contract.

## CLI

- [CLI Technical Reference](cli/README.md)
  Entry point for the current CLI technical reference and command subtree.

## Performance And Scalability

- [Large-Capture Performance Guidelines](large-capture-performance-guidelines.md)
  Current guidance for bounded large-capture and selected-flow behavior.
- [Selected-Flow Packet Cache Reference](selected-flow-packet-cache-rfc.md)
  Current cache-boundary and cache-budget reference despite the filename.

## Active Design RFCs

- [Advanced Flow Filter RFC](features/advanced-flow-filter-rfc.md)
  Current backend/compiler/text-format and CLI contract for Advanced Flow
  Filter.
- [Advanced Flow Filter UI RFC](features/advanced-flow-filter-ui-rfc.md)
  Current Qt/Tauri Advanced Flow Filter editing, document-state, file-workflow,
  and shared UI semantics reference.
- [Flow Aggregate Metadata RFC](features/flow-aggregate-metadata-rfc.md)
  Current compact per-connection aggregate metadata and PacketRef foundation.
- [Index v15 Container RFC](features/index-v15-container-rfc.md)
  Current stable v15 container/header and per-section compatibility contract.
- [Index v16 Container RFC](features/index-v16-container-rfc.md)
  Frozen target layout for the future stable v16 Statistics/metadata/detail
  architecture; not current production behavior.
- [Statistics, Reporting, and Large-Index Architecture RFC](features/statistics-reporting-index-rfc.md)
  Frozen Statistics/reporting architecture direction and migration rationale
  that pairs with the v16 container RFC; not current production behavior.

## Export

- [Smart Export](features/smart-export-v1.md)
  Current shared Smart Export packet-selection and single-output contract.
- [Per-Flow Smart Export](features/smart-export-per-flow-v1.md)
  Current per-flow Smart Export output contract.

## Developer Tools And Operational Docs

- [Import Validation](dissection-import-validation.md)
  Current developer validation-tool reference for import cutover and parity work.
- [Release Checklist](release-checklist.md)
  Current release-readiness checklist.
- [Manual Release Publish Checklist](manual-release-publish-checklist.md)
  Final manual publish checklist for the GitHub release.

Working release artifacts such as `release-notes-draft.md` remain useful, but
they are not part of the primary current technical authority layer.

## Active Backlog

- [UI Improvement Backlog](ui-improvement-backlog.md)
  Living engineering backlog; useful for future work, but not a definition of
  current product behavior.

## Historical Documentation

- [Historical Technical Documentation](history/README.md)
  Implemented RFCs, design evolution, audits, investigations, and superseded
  plans retained for rationale.
