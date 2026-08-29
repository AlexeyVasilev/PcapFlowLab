# Architecture

Pcap Flow Lab is a flow-first packet-capture analyzer with a shared backend for
desktop frontends and the CLI. The durable persisted model is packet and flow
metadata plus indexable session state; richer packet bytes, stream artifacts,
and selected-flow reconstruction remain on-demand.

## Main layers

- `core/io`
  - classic PCAP and current PCAPNG readers, packet seek/read helpers, and
    packet-writing export support
- `core/decode`
  - legacy packet-oriented decode helpers, including `PacketDecoder`
- `core/dissection`
  - unified registry-driven dissection engine used by current production import
- `core/domain`
  - flow keys, packet references, protocol-path identity, summaries, and other
    lightweight model types
- `core/services`
  - capture import, packet details, export, hinting, statistics, and related
    backend services
- `core/index`
  - exact-version sectioned index format and related source-capture validation
- `core/reassembly`
  - bounded ephemeral helpers used only for on-demand selected-flow work
- `app/session`
  - `CaptureSession` plus selected-packet, selected-flow, statistics, and
    export orchestration
- `app/frontend`
  - shared frontend/session adapters, bridges, and DTO shaping used directly by
    Tauri and by CLI commands where appropriate, alongside shared presentation
    helpers/contracts consumed across application surfaces
- `ui`
  - Qt desktop frontend
- `experimental/tauri-ui-spike`
  - experimental Tauri frontend over the same backend/session contracts
- `cli`
  - five-command CLI over the same backend/session architecture

## Processing paths

The architecture is easiest to understand as five distinct paths with
different persistence and cost profiles.

### 1. Raw capture open/import fast path

Raw capture import is the normal open path for `PCAP` and `PCAPNG`.

Production import is now driven by the unified registry-based dissection
engine plus shared import application code. This path is intentionally
packet-oriented and bounded:

- it decodes packet-level facts needed for grouping and summary;
- it builds canonical bidirectional flows;
- it records `PacketRef` metadata and source locators;
- it accumulates whole-capture counters and statistics inputs;
- it persists only lightweight reusable state into memory/indexable session
  structures.

It does not do global stream reconstruction, global reassembly, or full
transport-correct session analysis during open.

### 2. Persisted index path

Saved indexes reopen previously imported session state.

Current stable index format is revision `15` and uses exact-version
compatibility.
Loading a mismatched version fails and requires rebuilding the index from the
source capture.

The index persists reusable session metadata such as:

- grouped flow and connection state;
- packet references and related packet metadata;
- capture/source metadata used for source reattachment validation;
- protocol-path identity needed for stored flow grouping;
- persisted whole-session statistics inputs and related indexed state;
- persisted unrecognized-packet metadata in the current format.

The index does not persist:

- raw packet bytes;
- reassembly buffers;
- Stream artifacts;
- selected-flow ephemeral caches.

An index can therefore open in a metadata-only mode without current source
capture access. Reattaching the original source capture restores byte-backed
capabilities for the stored session, but it does not regroup or reinterpret the
indexed flow inventory.

### 3. Selected-packet lazy inspection

Selected-packet inspection is a separate lazy path.

Selected-packet inspection starts from the selected packet and its source
bytes. Normal packet facts remain selected-packet-oriented, and when an
explicitly supported byte view requires it, bounded selected-flow context may
also contribute authoritative reconstructed or derived bytes. This does not
imply global reassembly or unbounded contextual reading.

This path derives:

- structured packet `Summary`;
- packet `Bytes` views;
- exportable byte materialization.

This path is intentionally best-effort and conservative for malformed or
truncated packets. It may still expose useful partial facts without pretending
that unsupported deeper structure was decoded safely.

### 4. Selected-flow bounded ephemeral analysis

Selected-flow work is another separate path.

This path is:

- selected-flow only;
- on-demand;
- bounded by packet/item windows and packet-byte budgets;
- ephemeral rather than persisted.

It drives:

- the selected-flow packet list and packet-local enrichments;
- selected-flow Stream construction;
- Stream Item `Summary` and `Item Data`;
- selected-flow Analysis blocks and metrics.

Current bounded reassembly and reconstruction are heuristic utilities for this
path only. They are not global open-time state and do not imply full
TCP-correct recovery.

### 5. Frontend/session presentation path

Qt, Tauri, and CLI do not each implement their own packet parsing model.

Instead, shared session/frontend layers own the canonical session semantics and
shared presentation contracts where those contracts exist. Tauri uses the
frontend adapter/bridge boundary directly, CLI commands also consume
`FrontendSessionAdapter` where appropriate, and Qt uses `CaptureSession` and
related session/services directly for much of its controller behavior while
still sharing the same underlying backend model.

Each application surface still owns its own UI layout, interaction state,
command parsing, and rendering.

This boundary is what keeps:

- packet/grouping semantics;
- index/source-capture behavior;
- selected-packet byte views;
- Stream Item Data semantics;
- statistics data;
- export orchestration

aligned across multiple application surfaces.

## Canonical flow identity

Pcap Flow Lab groups packets into canonical bidirectional flows.

Identity is not just a normalized endpoint tuple. The current architecture uses
the normalized endpoint tuple plus interned protocol-path identity, so
namespace-bearing layers can split otherwise identical endpoint tuples.

This matters for overlay/tunnel and other path-bearing protocols where the same
transport tuple may legitimately exist in multiple distinct namespaces.

The user-facing `Endpoint A` / `Endpoint B` orientation remains a separate
presentation concept derived from the first observed packet in the grouped
flow. It does not perform client/server inference.

## Flow-grouping normalization settings

Raw capture import can optionally normalize some identity layers:

- ignore VLAN/MPLS layers when grouping flows;
- ignore GTP-U TEIDs when grouping inner flows.

These settings are applied only while building canonical flow identity during
raw import. They do not remove packet-visible protocol layers from packet
details, and they are not reapplied when an index is loaded later.

## Source-capture boundaries

The architecture deliberately separates indexed metadata from source packet
bytes.

- Raw capture sessions have immediate source-byte access because the capture
  itself is open.
- Index-backed sessions can remain useful without source bytes.
- Byte-backed features require a readable source capture that matches the
  stored source identity.

This boundary is central to the product:

- metadata-backed browsing, analysis, and statistics can survive index-only
  reopen;
- byte-backed packet inspection, Stream reconstruction/materialization, and
  packet-writing export cannot.

## PacketDecoder and unified dissection status

Production import has already cut over to the unified registry-driven
dissection engine.

However, the repository is not yet in a state where `PacketDecoder` is merely a
dead compatibility stub or validation-only oracle. Current production/session
code still uses `PacketDecoder` in non-import paths, including packet metadata
recovery and terminal transport payload related paths.

`PacketDetailsService` also remains a production selected-packet/details
consumer separate from the import-time engine path.

The correct architectural description today is therefore:

- unified dissection owns the production import/open path;
- legacy decoder/details code still has real production consumers outside that
  import path;
- the architecture is partially consolidated, but not yet reduced to one single
  packet-decoding implementation for every runtime use.

## Stream and reassembly boundaries

The Stream model is not a globally persisted session artifact.

Current architecture keeps Stream work:

- selected-flow only;
- on-demand;
- bounded;
- ephemeral.

HTTP, TLS, and QUIC-related selected-flow inspection can build meaningful
stream/item presentation when enough bytes are available, but this remains
bounded application logic rather than full transport/session reconstruction.

`Item Data` is likewise not a generic promise that every stream item has one
stable byte blob. It materializes authoritative item-owned bytes only where the
current protocol/item model actually retains them or reconstructs them with
clear ownership/provenance.

## Statistics boundaries

Whole-capture Statistics is session-level data, not selected-flow state.

Some statistics inputs are accumulated during raw import, while others are
reconstructed from persisted indexed metadata on load. Optional heavier
statistics sections are requested lazily by frontend/session presentation, but
that lazy loading is about DTO transport and rendering, not about inventing a
second parsing architecture.

## Export boundaries

Export behavior follows the same source-capture rules as other byte-backed
features.

- saving an index requires an attached source capture;
- byte export requires authoritative bytes for the selected packet/item;
- flow export / Smart Export ultimately requires source packet bytes.

The export surface is therefore another consumer of the same session/index/
source-capture architecture rather than a separate data path.

## Known architectural limits

The current architecture intentionally preserves a few important limits:

- no global open-time stream model;
- no raw packet bytes stored in indexes;
- no persisted reassembly buffers or Stream artifacts;
- no guarantee of transport-correct reconstruction for selected-flow work;
- no backward-compatible promise across index-format revisions;
- no claim that Qt and Tauri are identical in every UI detail, even though they
  share the same backend/session semantics where that backend contract exists.







