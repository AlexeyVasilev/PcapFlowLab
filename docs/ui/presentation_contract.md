# UI Presentation Contract

## Role

This document is the canonical current UI presentation contract for Pcap Flow
Lab.

It defines the shared product-facing semantics for the desktop frontends:

- Qt desktop UI, which remains the primary/reference desktop frontend;
- experimental Tauri desktop UI, which shares the same backend/session
  semantics.

CLI is not a future feature, but this document is not a CLI command contract.
CLI is mentioned only where shared backend/session presentation boundaries are
relevant.

This document does not attempt to preserve implementation history. Historical
engineering context belongs elsewhere.

Current protocol capability coverage is documented separately in
[protocol_support.md](../protocols/protocol_support.md).

## Scope

This contract defines shared semantic expectations for:

- active-session shell state;
- flows presentation;
- selected-flow packets;
- Packet Details;
- selected-flow Stream and Stream Item Details;
- Statistics;
- selected-flow Analysis;
- source-availability and unavailable states;
- shared presentation boundaries between backend/session and desktop frontends.

This contract does not require:

- pixel parity between Qt and Tauri;
- identical layouts, spacing, density, or colors;
- identical local widget state machines;
- identical dialog choreography where current implementation still differs.

## Shared architecture constraints

This contract stays aligned with the current backend/session architecture:

- capture open remains packet-oriented;
- deep stream/reassembly work is not moved into capture-open processing;
- selected-flow Stream remains bounded, selected-flow-only, and ephemeral;
- packet/source bytes are materialized lazily;
- source-unavailable/index-only behavior remains explicit;
- frontends must not fabricate unavailable byte content or unbounded previews.

## Frontend roles

- Qt is the reference desktop UI.
- Tauri is an experimental alternative desktop frontend.
- Both frontends share backend/session semantics and shared presentation helpers.

This contract defines shared semantic expectations while allowing
frontend-specific differences in:

- layout;
- density;
- colors;
- native controls;
- local interaction details.

## Active session shell

The shared shell contract includes:

- active input path;
- whether the active session was opened from a raw capture or an index;
- source-capture availability;
- expected source path when opening an index without accessible source bytes;
- opening/progress state;
- partial-open state;
- selected-flow / selected-packet / selected-stream-item dependent workspace
  state.

Opening a new capture or index must clear stale selected-flow, packet, stream,
analysis, and details state.

Open failure must not leave stale packet or stream details visible.

## Settings and capture-processing semantics

### Shared runtime settings slice

The current desktop frontends expose a shared runtime-safe settings slice that
includes:

- HTTP service-hint behavior;
- possible TLS/QUIC hint behavior;
- `Ignore VLAN and MPLS layers when grouping flows`;
- `Ignore GTP-U TEIDs when grouping inner flows`;
- Packet Details checksum validation;
- selected-flow Wireshark-filter visibility;
- Protocol Path column visibility.

### Settings dialog transaction model

Both desktop frontends follow the same high-level settings transaction model:

1. Opening the dialog initializes draft state from the current committed
   settings.
2. User edits update the draft state.
3. `OK` commits the draft.
4. `Cancel`/reject closes the dialog without applying the draft.

This shared dialog contract must not be confused with when a committed setting
visibly affects the current workspace.

- view/inspection settings may affect current presentation immediately after the
  draft is committed;
- capture-processing grouping settings are still import-time settings, even
  though they are also committed through the same `OK` flow.

### Grouping-setting semantics

The capture-processing grouping settings are:

- `Ignore VLAN and MPLS layers when grouping flows`
- `Ignore GTP-U TEIDs when grouping inner flows`

Shared semantic meaning:

- these settings are committed through the normal draft/`OK` settings flow;
- these settings affect raw-capture import/grouping behavior;
- changing them does not regroup an already opened raw session in place;
- the current capture must be reopened for new grouping behavior to take
  effect;
- an opened index preserves the grouping already stored in that index;
- current runtime settings must not reinterpret or regroup an already opened
  index.

### Grouping banners and limitation messaging

Raw-imported sessions may show informational grouping banners when the session
knows that the currently opened session was actually built with grouping
normalization enabled.

Index sessions are different:

- the product may explain that loaded indexes preserve stored grouping and are
  not regrouped by the current runtime setting;
- the canonical contract does not require index-session grouping-warning banners
  to be inferred from current checkbox state alone;
- current index metadata is not the authoritative source of “how this index was
  originally grouped” in the same way a currently imported raw session can be.

### Packet-versus-flow identity boundary

Grouping normalization affects flow identity and related flow/statistics
presentation. It does not remove actual per-packet metadata from packet
inspection surfaces.

For example:

- Packet Details may still show observed VLAN/MPLS/GTP-U packet metadata;
- flow-list Path presentation and Protocol Path Statistics follow normalized
  stored flow identity.

## Identifier and numbering semantics

The shared presentation contract distinguishes stable identifiers from visible
row/display numbering.

Stable identifiers include:

- `flow_index`
- `packet_index`
- `stream_item_index`

User-facing numbers are presentation fields. They must not be treated as the
stable backend identity.

Selection should be anchored to stable identifiers rather than visible sorted or
filtered row position.

## Flows presentation

### Core fields

Each flow row exposes shared semantic fields for:

- stable flow identity;
- address family;
- protocol;
- detected protocol;
- service;
- Endpoint A;
- Endpoint B;
- Protocol Path;
- packet count;
- original-byte count;
- fragmented-packet indicator/count when surfaced by the frontend.

Endpoint A / Endpoint B follow first-observed flow orientation.

### Protocol versus detected protocol

The product currently distinguishes:

- `Protocol`
- `Detected Protocol`

`Protocol` reflects the normalized transport/protocol identity used by the flow.

`Detected Protocol` reflects higher-level detection/presentation hints where the
current product surfaces them.

### Filtering and sorting

Flows filtering and sorting are currently frontend-side interaction behavior over
shared structured flow data.

The shared contract requires consistent semantic meaning for the fields being
filtered or sorted. It does not require backend-side filtering/sorting for the
desktop UIs.

### Selection and checked flows

The frontends distinguish:

- the active selected flow used by Packets / Stream / Packet Details / Analysis;
- checked flows used for batch actions.

These are not the same state.

### Wireshark filter

The product may surface a selected-flow Wireshark display filter generated from
shared flow/session semantics.

That filter is a presentation/export convenience, not the semantic source of
flow identity.

### Protocol Path

The flow-list `Path` column reflects stored/normalized flow identity path
presentation, not the full actual packet-layer tree of the currently selected
packet.

Compact Path badges/chips and related legend presentation are backed by shared
C++ path-presentation logic rather than independent frontend-maintained badge
tables.

## Selected-flow packets

The selected-flow packet list is:

- selected-flow-only;
- bounded;
- incrementally extendable;
- reset when selected flow changes.

Shared packet-row semantics include:

- flow-local row number;
- stable `packet_index`;
- direction;
- timestamp;
- captured length;
- original length;
- payload length;
- TCP flags where applicable;
- packet markers such as fragmentation or suspected retransmission where the
  frontend currently surfaces them.

Changing selected flow clears the active selected packet and stale packet
details.

## Packet Details

The current visible Packet Details tabs are:

- `Summary`
- `Bytes`

There is no current visible Packet Details:

- `Protocol` tab;
- `Raw` tab;
- `TCP Payload` tab;
- `UDP Payload` tab.

If internal formatter paths or protocol-text helpers still exist, they are
implementation details rather than current visible tabs.

### Summary

Packet `Summary` is a structured/model-driven packet inspection surface where
current implementation supports it.

It represents packet facts, decoded layers, warnings, and bounded structured
details. Frontends may render that structure differently, but the semantics come
from shared backend/session presentation.

### Bytes

Packet `Bytes` is backed by:

- stable shared backend byte-view descriptors;
- selected-view-only materialization;
- captured packet bytes and explicitly supported bounded derived views.

The contract does not imply:

- eager formatting of every byte view for every packet;
- full per-packet precomputed byte buffers;
- unbounded contextual reading.

Derived views may include bounded authoritative reconstructed/derived content
when the supported selected-packet byte-view contract requires it.

## Selected-flow Stream and Stream Item Details

The selected-flow Stream surface remains:

- selected-flow-only;
- bounded;
- on-demand;
- ephemeral.

The current visible Stream Item Details tabs are:

- `Summary`
- `Item Data`

There is no current visible Stream Item Details:

- `Protocol` tab;
- `Raw` tab;
- transport-specific payload tabs.

### Stream item summary

Stream item `Summary` is presentation backed by shared selected-stream/session
semantics.

### Item Data

`Item Data` follows the selected-flow contract:

- zero or one authoritative owner;
- selected-item-only materialization;
- owner may be packet-local or bounded reconstructed/derived owner;
- synthetic gap rows own no fabricated bytes.

The product must not fabricate authoritative bytes for rows that have no real
byte owner.

## Supported Protocols presentation

Pcap Flow Lab has a shared backend `SupportedProtocolCatalog`.

That backend catalog is the source of truth for the compact capability table
shown in:

- Qt `Help -> Supported Protocols`
- Tauri `Help -> Supported Protocols`
- the compact marked table in
  [protocol_support.md](../protocols/protocol_support.md)

Shared presentation architecture:

- backend `SupportedProtocolCatalog` is authoritative for the compact table;
- Qt and Tauri consume that shared catalog;
- frontends must not independently maintain divergent compact protocol-support
  tables;
- detailed engineering capability semantics remain documented in
  `protocol_support.md`.

This document intentionally does not duplicate the full catalog.

## Protocol Path presentation

Shared Protocol Path presentation distinguishes two different concepts:

- stored/normalized flow identity path;
- actual packet-layer structure of a selected packet.

### Shared frontend expectations

The product currently exposes Protocol Path through:

- the flow-list `Path` column;
- compact Path badges/chips;
- the Protocol Path Legend;
- Protocol Path Statistics modes:
  - `Kind overview`
  - `Identity tree`
  - `Terminal paths`
- structured `Show flows` / drill-down behavior where supported by the current
  frontend.

Qt and Tauri consume shared C++ protocol-path presentation mapping. They are not
expected to invent independent path semantics.

## Statistics

The Statistics contract aligns to current shared behavior:

### Always-visible core

- overview counters in the order `Packets`, `Flows`, `Original Bytes`,
  `Captured Bytes`;
- Capture Start / Capture End / Duration values;
- Transport Summary;
- IP Family Summary.

When the active capture was opened partially, the Statistics page must show a
compact warning that the values cover successfully imported packets only.

Shared always-visible Statistics semantics now also include:

- absolute UTC capture start/end timestamps;
- capture duration, with zero duration distinct from unavailable time;
- millisecond-precision visible formatting for capture-level timestamps and duration.

### Optional/lazy sections

The current optional independently collapsible/lazy statistics sections are:

- `Packet Size Distribution`
- `Flows by Packet Count`
- `Protocol Path Tree`
- `Detected Protocol Hints`
- `Capture Metrics`
- `Flow Characteristics`
- `Direction Distribution`
- `TCP Flags`
- `QUIC and TLS`
- `Top Flows by Original Bytes`
- `Top Endpoints and Ports`

These sections are based on whole-capture/session statistics, not selected-flow
state.

`Packet Size Distribution` loads one shared whole-capture DTO per expansion and
supports frontend-local `Captured` and `Original` display modes over the same
bucket boundaries. Mode switching changes only presentation and must not by
itself trigger another backend statistics request.

`Flows by Packet Count` likewise loads one shared whole-capture histogram DTO
per expansion and supports frontend-local `Flows`, `Captured bytes`, and
`Original bytes` modes over identical packet-count bucket membership.

`Direction Distribution` is one collapsible section containing both:

- `Packet Direction`
- `Data Direction (Original Bytes)`

`TCP Flags` is one collapsible whole-capture section containing:

- `SYN`
- `FIN`
- `RST`

Each row shows:

- `Packets`
- `Percent`

Shared semantics include:

- counts come from authoritative connection aggregate TCP flag counts rather
  than rescanning packet refs;
- percentages use the whole-capture TCP packet count as the denominator;
- `SYN` includes `SYN+ACK`;
- one packet may contribute to more than one row when multiple flags are set;
- zero TCP packets must render stable zero percentages rather than `NaN`/`Inf`.

`Top Flows by Original Bytes` is one collapsible whole-capture section
containing at most ten rows ranked by:

- original bytes descending;
- packet count descending;
- canonical flow index ascending for deterministic ties.

Each row shows:

- `Flow`
- `Endpoint A`
- `Endpoint B`
- `Protocol`
- `Detected Protocol`
- `Service`
- `Protocol Path`
- `Packets`
- `Captured`
- `Original`

Shared semantics include:

- `Flow` uses the same user-visible one-based numbering convention as the
  normal Flows list while remaining anchored to the same canonical flow index;
- `Endpoint A` / `Endpoint B` preserve first-observed orientation semantics;
- `Protocol` uses the same canonical transport/protocol presentation as the
  normal Flows list;
- `Detected Protocol` reuses the same effective possible-TLS/QUIC projection
  policy as the normal Flows list rather than owning an independent top-flow
  heuristic;
- `Service` uses the stored canonical service hint and renders a neutral `—`
  marker when empty;
- `Protocol Path` reuses the shared compact Protocol Path presentation for the
  stored `protocol_path_id`;
- `Packets`, `Captured`, and `Original` are metadata-backed connection totals;
- ranking is by `Original`, not by `Captured`.

`Top Endpoints and Ports` is one collapsible whole-capture section containing
two bounded tables:

- `Top Endpoints`
- `Top Ports`

Each table currently shows:

- identity column (`Endpoint` or `Port`)
- `Flows`
- `Packets`
- `Original Bytes`

Shared semantics include:

- both tables rank by original bytes descending, then packet count descending,
  then deterministic identity ascending;
- endpoint rows count distinct canonical flows involving that endpoint;
- port rows count distinct canonical flows involving each non-zero port number;
- a canonical flow contributes once per distinct non-zero port number, so a
  `4500 -> 4500` flow counts once for port `4500`, not twice;
- the section continues to share one metadata-backed top-statistics source with
  the top-flow section rather than triggering separate whole-flow traversals.

Shared semantics include:

- whole-capture totals;
- original bytes;
- percentages;
- packet-level derived metrics from `CapturePacketStatistics`;
- flow-level characteristics from canonical-flow totals;
- packet-direction distribution by canonical flow count;
- original-byte direction distribution by canonical flow count;
- structured drill-down / `Show flows` behavior where currently exposed.

This contract does not preserve implementation chronology for how those sections
were introduced.

## Analysis

Analysis is currently a selected-flow, on-demand workspace.

Shared semantic expectations:

- analysis is tied to the selected flow;
- it is not part of capture-open processing;
- it depends on bounded selected-flow data;
- it exposes overview/timeline/directional metrics;
- protocol/service information where currently surfaced;
- TCP control counts where applicable;
- burst/idle metrics;
- histograms;
- sequence preview and export.

This contract records stable visible semantics, not a new analysis RFC and not a
promise of identical Qt/Tauri layout.

## Loading, unavailable, and source states

Frontends must clearly distinguish:

- no capture loaded;
- opening/progress;
- partial open;
- no selected flow;
- packet or stream loading;
- Analysis loading or unavailable;
- source capture unavailable;
- bounded `Load More` states;
- index source attachment workflows.

Availability should be expressed as real session/source state, not by fabricating
content or hiding meaningful limitations.

## Backend and frontend ownership summary

Shared backend/session/frontend-neutral presentation should own:

- structured flow/session facts;
- structured Statistics DTOs;
- Packet Summary structure where current implementation supports it;
- Packet Bytes descriptors and selected-view materialization;
- Stream Item Data ownership/materialization;
- compact Supported Protocols catalog data;
- Protocol Path presentation mapping.

Frontend-specific layers should continue to own:

- layout;
- density;
- colors;
- local selection widgets;
- table virtualization/windowing;
- local interaction choreography;
- frontend-specific wording where it is not part of a shared semantic contract.
