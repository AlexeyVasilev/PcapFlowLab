# Non-Terminal IP UI Integration RFC

Status: proposed feature contract.

This RFC defines how Pcap Flow Lab should expose already-retained
`NonTerminalIpContext` Flow identity metadata through Advanced Flow Filter,
Protocol Path Statistics, and compact capture-grouping provenance UI.

The underlying identity, import, storage, and index contract remains
authoritatively defined by
[Non-Terminal IP Flow Identity RFC](non-terminal-ip-flow-identity-rfc.md).
This document is an extension of that contract, not a replacement for it.

## Purpose

The implemented Flow identity model already distinguishes otherwise-identical
terminal Flows by:

```text
terminal tuple
+ normalized ProtocolPathId
+ NonTerminalIpContextId
```

This feature makes that retained metadata visible and usable after import/open:

- Advanced Flow Filter can match non-terminal IP addresses and networks.
- Protocol Path Statistics can show a context-sensitive identity tree.
- Qt and Tauri can present compact loaded-capture grouping provenance.

No parser/import/Flow-identity redesign is planned. The feature consumes
existing metadata after import/open.

## Non-Goals

This RFC explicitly defers:

- non-terminal Endpoint A/B filtering;
- directional source/destination non-terminal filtering;
- outer/intermediate transport ports;
- retaining ignored IP contexts;
- packet rescanning for filtering;
- Flow identity changes;
- ProtocolPath semantic changes;
- concrete addresses in `ProtocolPathRegistry`;
- a new index revision;
- new import parsing;
- top outer-IP talker statistics;
- a generic statistics framework redesign;
- a generic settings framework redesign.

## Existing Metadata Contract

Current implementation already retains the metadata needed for this feature:

- `FlowKeyV4` / `FlowKeyV6` carry `NonTerminalIpContextId`;
- `ConnectionKeyV4` / `ConnectionKeyV6` carry `NonTerminalIpContextId`;
- `CanonicalFlowMetadata` carries `non_terminal_ip_context_id`;
- `CaptureState` owns `NonTerminalIpContextRegistry`;
- index revision `20` persists the context registry and per-Flow/Connection
  context ID;
- index revision `20` persists the capture import settings snapshot.

`NonTerminalIpContextId = 0` remains reserved for empty/default/ignored
context. `NonTerminalIpContextRegistry::find(0)` is not an owned non-empty
context.

## Index Compatibility

Current stable index revision `20` is sufficient.

Required metadata already exists:

- `ProtocolPathRegistry`;
- `NonTerminalIpContextRegistry`;
- per-Flow/Connection `NonTerminalIpContextId`;
- capture import settings snapshot.

No new index revision is required. No new persisted derived statistics should
be added.

## Import/Open Performance Contract

This feature must not change the raw capture parsing/grouping hot path.

Do not add:

- new packet parsing;
- a second packet pass;
- source capture re-read;
- additional per-packet retained metadata;
- `PacketRef` growth;
- Flow identity changes;
- Connection identity changes;
- index format changes.

Filtering and statistics consume already-retained flow metadata, protocol-path
metadata, context metadata, and import-provenance metadata after import/open.

## Advanced Filter Overview

The existing terminal IP filter contract is preserved.

Existing predicates such as:

```text
ip.either.include = 192.0.2.1
ip.a.include = 192.0.2.0/24
ip.b.exclude = 2001:db8::/32
```

continue to refer only to terminal/user-facing Flow Endpoint A/B addresses.
Their semantics must not change.

Non-terminal IP filtering is a separate criteria family.

## Non-Terminal IP Filter Grammar

Canonical text grammar:

```text
non_terminal_ip.outer.include = 192.0.2.1
non_terminal_ip.outer.exclude = 192.0.2.0/24

non_terminal_ip.intermediate.include = 2001:db8::1
non_terminal_ip.intermediate.exclude = 2001:db8::/32

non_terminal_ip.any.include = 10.0.0.1
non_terminal_ip.any.exclude = 10.0.0.0/8
```

Implementation should follow the existing parser punctuation, spacing, ordering,
and canonical formatting conventions used by `.filter` v3.

The new section enabled key should follow current section conventions:

```text
section.non_terminal_ip.enabled = true | false
```

All sections default to enabled. Canonical formatting should omit default
`true` assignments and emit only non-default `false` assignments.

## Non-Terminal IP Scopes

The scope token selects which `NonTerminalIpContext` levels are considered:

- `outer`: only level `0`;
- `intermediate`: levels `1 .. N-1`;
- `any`: all levels.

If context is empty:

- `outer` matches no level;
- `intermediate` matches no level;
- `any` matches no level.

If context contains exactly one level:

- `outer` evaluates level `0`;
- `intermediate` has no level and matches no flow;
- `any` evaluates level `0`.

## Direction Contract

Version 1 is deliberately direction-agnostic.

Do not add any of these concepts to non-terminal IP filtering in this feature:

- Endpoint A;
- Endpoint B;
- source;
- destination.

For every candidate context level, a predicate matches if the address matches:

```text
level.source OR level.destination
```

This symmetry is important. Because matching is invariant under
source/destination reversal, the evaluator does not need to reconstruct
user-facing first-observed Endpoint A/B orientation from canonical
`NonTerminalIpContext` orientation.

Future directional non-terminal filtering may be added later, but it is out of
scope for this feature.

## IPv4, IPv6, And CIDR

Reuse existing terminal IP matching semantics where applicable:

- IPv4 exact;
- IPv4 CIDR;
- IPv6 exact;
- IPv6 CIDR.

Do not invent a second CIDR interpretation.

The implementation may reuse existing low-level IP/CIDR parsing and matching
helpers. The non-terminal criteria should remain structurally separate from the
existing terminal address criteria.

Recommended model direction:

```text
AdvancedFlowFilterNonTerminalIpScope
    outer
    intermediate
    any

AdvancedFlowFilterNonTerminalIpCriteria
    IPv4 include/exclude predicates
    IPv6 include/exclude predicates
```

Each predicate carries:

- scope;
- exact/CIDR kind;
- address/network;
- prefix length.

Do not force a generic address framework merely to share a few helpers.

## Include/Exclude Semantics

Non-terminal IP criteria form their own Advanced Filter category.

Within that category:

- include predicates use the existing include-group semantics;
- matching exclude predicates reject the Flow;
- predicates with different non-terminal scopes participate in the same
  include group for the non-terminal-IP category;
- there is no hidden AND rule between `outer`, `intermediate`, and `any`.

The non-terminal-IP category combines with other active Advanced Filter
categories using the existing overall AND semantics.

As with existing categories, an empty include set imposes no positive
restriction, and an empty exclude set rejects nothing.

## Filter Metadata Access

Current filter evaluation supports both:

- `ListedConnectionRef`;
- `CanonicalFlowMetadata`.

Both already expose `NonTerminalIpContextId`, but the evaluator currently does
not receive a context registry.

Recommended integration is a lightweight evaluation context/resolver:

```text
AdvancedFlowFilterEvaluationContext
    const NonTerminalIpContextRegistry*
    non-terminal-IP metadata availability/status
```

`CaptureSession` should construct the context from:

- raw capture: `CaptureState::non_terminal_ip_context_registry`;
- index-backed capture: persisted index v20 `NonTerminalIpContextRegistry`.

Do not copy `NonTerminalIpContext` into every `CanonicalFlowMetadata` row.
Do not add source-packet reads.

## Ignored-Context Filter Behavior

If a capture was imported with:

```text
Ignore non-terminal IP endpoints when grouping flows = Yes
```

then endpoint contexts were intentionally not retained.

A filter containing any `non_terminal_ip.*` predicate must not silently
evaluate to zero matches. It must return an explicit capture-dependent
unavailable/applicability status.

Conceptual message:

```text
Non-terminal IP metadata was not retained because it was ignored when this
capture was imported.
```

This is not a syntax error. The filter document is syntactically valid; it is
not applicable to this loaded capture/index.

This differs from:

```text
Ignore non-terminal IP endpoints when grouping flows = No
```

with a capture that simply contains no non-terminal IP levels. In that case the
filter is valid and naturally matches zero Flows.

Structured Qt/Tauri editors should surface the same backend-owned condition and
disable or mark the non-terminal-IP section unavailable for that capture.

Do not rescan packets to recover discarded context.

## Raw/Index Parity

Non-terminal IP filtering must behave identically for:

- freshly imported raw capture;
- reopened compatible index v20.

No original source capture bytes are needed. No packet re-dissection is
allowed.

Future tests should cover exact raw/index parity for:

- IPv4 exact;
- IPv4 CIDR;
- IPv6 exact;
- IPv6 CIDR;
- `outer`;
- `intermediate`;
- `any`;
- ignored-context unavailable status.

## Advanced Filter UI

Qt and Tauri structured editors should expose a new section:

```text
Non-terminal IP addresses
```

Rows should follow the existing IP/CIDR editor pattern where practical, but the
scope choices are:

- `Outer`;
- `Intermediate`;
- `Any non-terminal IP`.

There is no A/B selector.

The section should participate in the existing document-state, enabled-state,
include/exclude, Apply/Cancel, Open/Save, and validation workflow.

## Protocol Path Statistics Mode

Add a fourth shared statistics mode:

```cpp
ProtocolPathStatisticsMode::identity_tree_ip_context = 3
```

Existing values remain unchanged:

```cpp
kind_overview = 0
identity_tree = 1
terminal_paths = 2
```

Existing modes must not change behavior.

User-facing label:

```text
Identity Tree + IP Context
```

The mode is a statistics/presentation composition of:

```text
ProtocolPath + NonTerminalIpContext
```

It does not change `ProtocolPath` itself.

## Statistics-Only Composite Layer Identity

Define a statistics-only tree segment conceptually as:

```text
structural LayerKey
+ optional NonTerminalIpLevel decoration
```

Do not put concrete IP addresses into:

- `ProtocolPath`;
- `ProtocolPathId`;
- `ProtocolPathRegistry`.

For non-IP structural layers:

```text
decoration = none
```

For non-terminal IPv4/IPv6 layers:

```text
decoration = corresponding NonTerminalIpLevel
```

For the effective terminal IPv4/IPv6 layer:

```text
decoration = none
```

## Context-To-Path Mapping

Mapping is deterministic.

Walk `ProtocolPath` layers in structural order. Maintain a context-level index
starting at `0`.

For each IPv4/IPv6 layer:

```text
if context-level index < NonTerminalIpContext.size():
    decorate this IP layer with that context level
    increment context-level index
else:
    leave the IP layer undecorated
```

Thus exactly the first `NonTerminalIpContext.size()` IPv4/IPv6 occurrences in
the path receive concrete endpoint decoration.

The effective/terminal IP layer is not part of `NonTerminalIpContext` and
therefore remains undecorated.

If implementation detects metadata/path inconsistency, it must not silently
attach addresses to an arbitrary IP layer. It should surface an unavailable or
diagnostic status at the nearest practical boundary.

Do not modify packet parsing to create a new mapping marker unless later
implementation proves the current metadata contract insufficient. Current audit
found the existing metadata sufficient.

Focused tests should cover existing supported paths:

- GTP-U;
- VXLAN;
- Geneve;
- GRE direct IP;
- GRE/TEB where applicable;
- EoIP;
- IP-in-IP;
- nested multiple-IP encapsulation;
- IPv4/IPv6 mixed nesting.

## Statistics Display

Display canonical non-terminal endpoint pairs as bidirectional identity, not
traffic direction.

Conceptual Qt/Tauri display:

```text
IPv4 [192.0.2.1 ↔ 192.0.2.2]
```

ASCII text export should use a safe representation:

```text
IPv4 [192.0.2.1 <-> 192.0.2.2]
```

Do not call these values:

- Endpoint A;
- Endpoint B;
- Source;
- Destination.

`NonTerminalIpContext` orientation is canonical identity orientation, not
first-observed UI direction.

## Statistics Aggregation

Existing `Identity tree` remains structural:

```text
same ProtocolPath
different NonTerminalIpContext
    -> same existing structural branch
```

New `Identity Tree + IP Context` mode is context-sensitive:

```text
same ProtocolPath
different context at a decorated IP level
    -> separate branches beginning at the first differing decorated layer
```

Aggregation is conceptually based on the ordered sequence:

```text
LayerKey + optional context decoration
```

for each path prefix.

Do not alter `ProtocolPathRegistry` cardinality.

## Statistics Row Model

Prefer keeping:

```text
ProtocolPathStatisticsRow::path
```

structural.

Add only the minimum statistics-specific metadata needed for the new mode. A
recommended direction is for an IP-context-decorated row/node to retain an
optional `NonTerminalIpLevel` associated with that node.

Rows already have:

```text
node_id
parent_node_id
```

The implementation should reconstruct the composite ancestor path by walking
the summary tree. Do not store a complete duplicated `NonTerminalIpContext`
prefix in every descendant row if parent-node relationships can represent the
same identity.

Presentation strings may contain enriched display text while structural
`ProtocolPath` data remains unchanged.

## Row Selection And Flow List Filtering

Selecting a row in `Identity Tree + IP Context` must filter the Flow List using
both:

- structural path prefix;
- relevant IP-context prefix represented by the selected branch.

It must not fall back to structural `ProtocolPath` matching only.

Do not synthesize Advanced Filter text solely to implement statistics
selection.

For resident/raw sessions, existing summary membership machinery may be reused.

For index-backed sessions, existing persisted/path-only protocol-path
membership cannot distinguish `NonTerminalIpContext`. Use current
`CanonicalFlowMetadata` plus:

- `ProtocolPathRegistry`;
- `NonTerminalIpContextRegistry`;

to perform context-aware matching for the selected composite node.

Prefer avoiding a large duplicated per-node Flow membership pool for
index-backed mode if the existing scan-on-selection pattern remains bounded and
consistent with current behavior. The selected node's composite prefix can be
reconstructed from its parent chain plus per-node context decoration.

## Statistics Availability

If capture import used:

```text
Ignore non-terminal IP endpoints when grouping flows = Yes
```

then `Identity Tree + IP Context` must be explicitly unavailable.

Do not silently show ordinary `Identity tree` under the enriched mode name.

Conceptual UI:

```text
Identity Tree + IP Context
Unavailable: non-terminal IP metadata was not retained for this capture.
```

Backend/session API should expose explicit availability/status so Qt, Tauri,
exports, and other callers do not independently infer this.

If the import setting was `No` but the capture simply contains no non-terminal
IP levels, the mode is available and may naturally look like an ordinary
structural tree because there is nothing to decorate.

## Statistics Performance

The fourth mode must remain lazy/on-demand.

Use only already-retained:

- flow metadata;
- `ProtocolPathRegistry`;
- `NonTerminalIpContextRegistry`.

Do not add:

- packet scan;
- source capture read;
- import-time statistics expansion;
- new persisted derived statistics.

Context splitting may increase node cardinality. Avoid eager formatting of
IPv6/address strings before DTO/text presentation where practical.

Do not add an arbitrary cardinality cap without evidence.

## Qt/Tauri Integration

The new statistics mode and new filter semantics are shared C++ behavior. Qt
and Tauri remain thin presentation layers.

Both frontends must support mode value `3` explicitly. Do not rely on
unknown-mode fallback to `kind_overview`.

Structured Advanced Filter editors in both UIs should expose
`Non-terminal IP addresses` with:

- `Outer`;
- `Intermediate`;
- `Any non-terminal IP`;
- no A/B selector.

## CLI And Export Scope

The core/session statistics mode should be shared. Qt/Tauri statistics and
normal Protocol Path text export must understand the new mode.

Current CLI architecture parses public mode tokens for:

- `kind-overview`;
- `identity-tree`;
- `terminal-paths`.

It also uses shared protocol-path text rendering and has fast-index statistics
paths that currently request existing modes explicitly.

Product scope for this feature is UI-first. Adding a new public CLI token is
therefore deferred unless implementation finds it cheap and naturally aligned
with the shared code changes.

Even if public CLI selection is deferred, all switches/mappings that can
receive enum value `3` must handle it safely and must not accidentally fall
back to `kind_overview`.

## Capture Grouping Settings UI

The UI must distinguish two concepts.

### Settings For The Next Raw Capture Import

Group the three identity-normalization settings together:

- `Ignore VLAN and MPLS layers when grouping flows`;
- `Ignore GTP-U TEIDs when grouping inner flows`;
- `Ignore non-terminal IP endpoints when grouping flows`.

Use one shared explanatory note for the group:

```text
Applied when importing the next raw capture.
Existing indexes keep their stored flow grouping.
```

Do not repeat the same help paragraph under every checkbox.

This is configuration for future raw imports.

### Provenance Of The Current Opened Capture/Index

Show non-default Flow grouping provenance compactly.

Conceptual example:

```text
Flow grouping: VLAN/MPLS ignored · GTP-U TEID ignored · Non-terminal IP ignored
```

Only active/non-default grouping relaxations need to occupy persistent space.

If none are active, no persistent grouping warning/status is needed.

Detailed values can remain available in capture/statistics details. Do not mix
loaded-capture provenance with the current mutable application Settings values.

## Warning Severity

Non-default grouping settings are intentional expert choices.

Treat the compact loaded-capture grouping indicator primarily as informational
provenance, not as a large error/warning panel. It should remain visible enough
that users understand why Flow counts/grouping may differ.

Prefer:

- compact banner;
- status line;
- chips/tags;
- details tooltip/popover.

Exact visual styling remains a frontend implementation decision.

## Compact Grouping Status Contents

The compact Flow-grouping provenance concerns only:

- VLAN/MPLS grouping normalization;
- GTP-U TEID grouping normalization;
- non-terminal IP endpoint grouping normalization.

Do not include unrelated import/runtime settings such as:

- HTTP request path as service hint;
- checksum validation;
- possible TLS/QUIC presentation settings.

## Existing Fixture Families

Prefer current deterministic fixtures for implementation coverage. Existing
families provide useful coverage for:

- outer-only context;
- multiple non-terminal levels;
- different outer endpoints;
- IPv4/IPv6 contexts;
- ignore-non-terminal-IP import mode;
- raw/index parity.

Known relevant fixture families include:

- `tests/data/parsing/gtpu/`;
- `tests/data/parsing/vxlan/`;
- `tests/data/parsing/geneve/`;
- `tests/data/parsing/gre/`;
- `tests/data/parsing/eoip/`;
- `tests/data/parsing/ip_encapsulation/`;
- `tests/data/parsing/mpls_pw/` where GRE/TEB/MPLS path behavior is relevant.

Do not require new PCAPs unless implementation later finds a genuinely missing
semantic case.

## Implementation Stages

Keep work in one feature branch with coherent, reviewable commits.

### Stage 1 - RFC Approval

Approve this RFC and resolve any open product questions.

### Stage 2 - Advanced Filter Backend TDD

Implement:

- model;
- grammar;
- compile;
- evaluation;
- registry access;
- raw/index parity;
- unavailable/applicability status.

### Stage 3 - Advanced Filter Qt/Tauri Integration

Expose the structured editor section in both frontends with shared backend
semantics.

### Stage 4 - Identity Tree + IP Context Backend TDD

Implement:

- enum mode;
- composite aggregation;
- context-to-path mapping;
- row membership/selection;
- unavailable status;
- raw/index behavior.

### Stage 5 - Qt/Tauri Statistics Integration And Text Export

Expose mode `3` explicitly, render context-decorated rows, and update text
export handling.

### Stage 6 - Grouping Settings/Provenance UI Cleanup

Consolidate next-import settings notes and add compact loaded-capture grouping
provenance.

### Stage 7 - Documentation Synchronization And Branch Audit

Update current technical and user-facing documentation after implementation.
Do not modify historical docs.

## Documentation Impact

Later implementation stages should update current docs, including:

- `docs/features/non-terminal-ip-flow-identity-rfc.md`;
- `docs/features/advanced-flow-filter-rfc.md`;
- `docs/features/advanced-flow-filter-ui-rfc.md`;
- `docs/protocols/protocol_path_flow_identity.md`;
- `docs/ui/presentation_contract.md`;
- relevant `user_docs/**` pages after UI behavior exists.

Do not update end-user docs during this RFC-only pass.

## Decision Summary

- The existing non-terminal IP identity/storage/import contract remains
  authoritative.
- Terminal `ip.either/a/b` Advanced Filter semantics remain unchanged.
- Non-terminal IP filtering is a separate criteria family.
- Version 1 non-terminal IP filtering is direction-agnostic.
- Non-terminal predicates match either address in a selected context level.
- Ignored-context captures return explicit unavailable/applicability status.
- Raw and index v20 semantics must be identical.
- Add `ProtocolPathStatisticsMode::identity_tree_ip_context = 3`.
- `Identity Tree + IP Context` is a statistics-only composition.
- Concrete IP addresses remain out of `ProtocolPathRegistry`.
- Row selection in the new statistics mode is context-aware.
- The feature is compatible with current index revision 20.
- CLI public token support is deferred unless it naturally falls out of shared
  implementation work.
- Compact grouping provenance is informational, not an error state.
