# Protocol Path Flow Identity

## Goal

Define a reviewable design for protocol-path-aware flow identity in Pcap Flow Lab.

The intended long-term direction is:

```cpp
struct FlowKeyV2 {
    NormalizedEndpointTuple tuple;
    ProtocolPathId protocol_path_id;
};
```

This document began as the RFC/design note for protocol-path-aware flow identity.

Current repository state:

- protocol-path extraction and interning are implemented;
- `FlowKeyV2` is enabled through `protocol_path_id` on flow identity and normalized connection identity;
- stable index serialization persists protocol-path registry data plus flow/connection `protocol_path_id`;
- the flow list can now expose protocol paths as compact badge/chip presentation derived from the interned registry;
- the flow-list Path column is intended to show the intermediate link / shim / overlay path to the effective flow protocol rather than duplicate terminal control protocols already shown in the Protocol column;
- both the Qt UI and the Tauri spike can consume the same C++ protocol-path presentation data for flow-list display;
- flow-list protocol-path presentation is now resolved lazily or deduplicated per unique `ProtocolPathId` rather than materialized eagerly per flow row;
- session flow rows now carry only `protocol_path_id` for protocol-path-aware flow-list presentation; full path text, compact text, and badges are resolved lazily from the capture-level registry when a frontend actually needs them;
- both UI frontends now expose a protocol path legend derived from the centralized C++ presentation mapping;
- the Tauri spike now supports runtime show/hide of the flow-list Path column;
- runtime protocol-path statistics trees now exist in the Statistics tab for both UI frontends;
- kind-overview and identity-tree protocol-path statistics are now collapsible in both UI frontends;
- both the Qt UI and the Tauri spike can now apply a selected protocol-path statistics node as a runtime structured flow-list filter.

## Flow List Presentation

The current UI may expose protocol-path-aware flow identity as a compact flow-list column, for example:

```text
[EII] [Ip4] [UDP] [Vx] [EII] [Ip4] [TCP]
```

Important scope boundaries:

- this badge/chip presentation is explanatory UI only;
- it does not change `FlowKeyV2`, decode behavior, import behavior, or stable index semantics;
- it is derived lazily from the capture-level `ProtocolPathRegistry`, not stored redundantly per packet or duplicated eagerly into every flow row payload;
- both UI frontends should consume centralized C++ presentation data rather than duplicating abbreviation or color-key mapping in UI-specific code;
- badge tooltips may include namespace identifiers such as VLAN VID, MPLS label, VXLAN VNI, Geneve VNI, or GTP-U TEID;
- current badge coverage also includes parser-supported shim layers such as LLC/SNAP, MPLS PW, PBB, PPPoE, and PPP where those layers lead to normal flows;
- higher-level application hints such as TLS, QUIC, DNS, or HTTP are intentionally excluded from protocol-path badges because they are not part of flow identity in v1.

Still deferred:

- protocol-path drill-down workflows beyond the current Statistics-to-Flows structured filter;
- persistence for the Tauri Path-column visibility toggle.

Implementation note:

- the Qt flow list resolves path text / compact text / badges on demand from `protocol_path_id` and caches the resulting presentation by unique id;
- the Qt flow list keeps one owning `all_items_` store plus visible-row indices into that store so filtering does not duplicate QString-heavy rows in memory;
- the Tauri spike receives protocol-path presentations once per unique `protocol_path_id` and looks them up when rendering flow rows;
- this optimization reduces memory pressure in Fast mode without changing FlowKeyV2 identity, protocol-path statistics semantics, or protocol-path filtering behavior.

## Runtime Protocol-Path Statistics

The current implementation now computes a runtime protocol-path prefix tree from loaded capture state.

Important properties:

- statistics are computed lazily from flow-level `protocol_path_id` plus the capture-level `ProtocolPathRegistry`;
- the tree is available after both fresh PCAP import and opening from a saved index;
- protocol-path statistics are still runtime-only and are not persisted in the stable index;
- each statistics mode is built on demand and then reused from the capture-session cache;
- opening a capture no longer eagerly builds all protocol-path statistics modes up front;
- expanded/collapsed state is presentation-only, resets on capture or mode changes, and is not persisted;
- search and top-N remain future work.

The current UI exposes three runtime view modes:

1. `Kind overview`
   - default mode;
   - aggregates by ordered layer kind only;
   - presented as a collapsible tree;
   - namespace identifiers are ignored for grouping and row display;
   - examples:
     - `VXLAN(vni=100)` and `VXLAN(vni=200)` aggregate under `VXLAN`;
     - `GTP-U(teid=...)` aggregates under `GTP-U`;
     - `MPLS(label=102)` and `MPLS(label=200)` aggregate under `MPLS`;
   - repeated layers remain positional, so `MPLS -> MPLS -> IPv4` stays a nested two-level MPLS stack.

2. `Identity tree`
   - exact `FlowKeyV2` explanation mode;
   - presented as a collapsible tree;
   - current identifier-bearing layers such as `VXLAN(vni=...)`, `Geneve(vni=...)`, `GTP-U(teid=...)`, `VLAN(vid=...)`, and `MPLS(label=...)` remain distinct tree nodes.

3. `Terminal paths`
   - flat list of complete terminal protocol paths only;
   - remains non-collapsible;
   - intermediate prefixes are omitted;
   - terminal rows currently use exact identity paths for traceability.

Counting semantics:

- in both prefix-tree modes, each recognized flow contributes `+1` to every prefix of its protocol path;
- in both prefix-tree modes, each recognized flow contributes its recognized packet count to every prefix of that same path;
- in both prefix-tree modes, each recognized flow contributes its flow-level recognized original byte count to every prefix of that same path;
- in terminal-path mode, each flow contributes once to its complete path only;
- unrecognized packets are excluded for now because they do not yet participate in the same stable protocol-path model;
- `flow_percent` uses total recognized flow count as the denominator;
- `packet_percent` uses total capture packet count as the denominator, so packet shares remain anchored to the capture rather than to recognized flows only.
- `original_byte_percent` currently uses total protocol-path-recognized original bytes as the denominator, because the capture summary does not yet carry a separate capture-wide original-byte total for this view.

Presentation notes:

- the Qt Statistics tab shows a compact indented `Layer / Flows / Packets / Original Bytes` tree plus a mode selector;
- in tree modes, both frontends expose per-row expanders plus `Expand all` / `Collapse all` controls;
- visible tree rows now display readable per-layer names such as `Ethernet II`, `IPv4`, `TCP`, `VLAN (VID 200)`, `MPLS (label 102)`, `VXLAN (VNI 100)`, and `GTP-U (TEID 0x01020384)`;
- count and original-byte columns now use centralized formatted `value (percent)` text in both frontends;
- full prefix path text remains available for tooltips/debug, while compact path text remains useful for badges and flow-list presentation;
- the Qt tree now uses a dedicated list model plus `ListView` virtualization, keeps a bounded internal height so large captures do not instantiate every row eagerly, and loads the active statistics mode when the Statistics tab actually needs it;
- the Tauri spike keeps the tree inside a bounded internal scroll block and now fetches protocol-path statistics rows per mode on demand instead of shipping all three modes in the initial overview payload;
- for very large sessions, the Tauri spike now keeps async open progress/cancel plus overview/statistics available but skips eager full flow-row loading above `250,000` flows so multi-million-flow indexes do not hang the shell;
- ordering is deterministic: descending `packet_count`, then descending `flow_count`, then path text.

### Structured Flow Filter

Both frontends can now apply a selected protocol-path statistics row as a runtime structured flow-list filter.

Current behavior:

- the user selects a protocol-path row in the Statistics tab and clicks `Show flows`;
- the app switches to the Flows tab and applies a snapshot flow-membership filter for that row;
- the Flows tab shows a read-only protocol-path filter chip with a dedicated `Clear` action;
- the normal text filter remains independent and combines with the protocol-path filter using logical `AND`;
- clearing the protocol-path filter restores the text-filter-only flow list;
- the structured filter is runtime UI state only and is not persisted in the index.

Membership semantics:

- `Kind overview` applies kind-prefix membership;
- `Identity tree` applies identifier-aware prefix membership;
- `Terminal paths` applies exact full terminal-path membership.

The current implementation intentionally uses a snapshot of runtime flow indices rather than persisting node selections or node ids.

## Problem Statement

Tuple-only flow grouping is not sufficient once the same effective endpoint tuple can appear behind different shim or tunnel paths.

The current implementation now groups flows by:

- normalized source IP;
- normalized destination IP;
- normalized source port;
- normalized destination port;
- terminal transport protocol;
- `protocol_path_id`.

The original problem this RFC set out to solve was that flow grouping used only an effective normalized endpoint tuple:

- source IP;
- destination IP;
- source port;
- destination port;
- terminal transport protocol.

That is not sufficient once the same effective tuple can appear behind different shim or tunnel paths.

Examples that must become distinct flows:

1. Direct versus shimmed transport:

```text
EthernetII -> IPv4 -> TCP
EthernetII -> MPLS(label=102) -> VLAN(vid=200) -> IPv4 -> TCP
```

Even if the IPv4 addresses and TCP ports are identical.

2. Same inner tuple but different VXLAN VNI:

```text
EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP
EthernetII -> IPv4 -> UDP -> VXLAN(vni=200) -> EthernetII -> IPv4 -> TCP
```

3. Same inner tuple but different Geneve VNI.

4. Same inner tuple but different GTP-U TEID.

This is already visible in current fixture coverage, for example:

- `tests/data/parsing/vxlan/10_vxlan_same_inner_tuple_different_vni.pcap`

The same metadata is also needed for future:

- protocol-path statistics;
- prefix/exact protocol-path filters;
- identifier filters such as VLAN VID, MPLS label, VNI, or TEID.

## Terminology

- `effective endpoint tuple`
  - The normalized IP/transport tuple currently used for flow grouping after shim or overlay continuation resolves the final network/transport headers.
- `protocol path`
  - The ordered sequence of protocol layers that leads to the effective tuple.
- `layer key`
  - One protocol-path element, including the layer kind and any stable namespace identifier for that layer.
- `layer identifier`
  - Stable numeric metadata that materially changes flow namespace for a given layer, such as VLAN VID, MPLS label, VXLAN VNI, Geneve VNI, or GTP-U TEID.
- `protocol path registry`
  - An interned mapping from `ProtocolPath` value objects to compact `ProtocolPathId` integers.
- `protocol path id`
  - A compact stable-per-session identifier used in `FlowKeyV2`, packet metadata, and later statistics/filter structures.
- `flow namespace`
  - The identity context created by the ordered protocol path and its namespace identifiers, distinct from the endpoint tuple alone.
- `prefix path`
  - A leading subsequence of a full protocol path, for example `EthernetII -> MPLS(label=102)`.
- `exact path`
  - The full ordered path to the terminal effective transport layer, for example `EthernetII -> MPLS(label=102) -> VLAN(vid=200) -> IPv4 -> TCP`.

## Proposed Model

### Flow identity

Conceptually:

```cpp
struct NormalizedEndpointTupleV4 {
    std::uint32_t src_addr;
    std::uint32_t dst_addr;
    std::uint16_t src_port;
    std::uint16_t dst_port;
    ProtocolId protocol;
};

struct NormalizedEndpointTupleV6 {
    std::array<std::uint8_t, 16> src_addr;
    std::array<std::uint8_t, 16> dst_addr;
    std::uint16_t src_port;
    std::uint16_t dst_port;
    ProtocolId protocol;
};

using ProtocolPathId = std::uint32_t;
```

Then:

```cpp
struct FlowKeyV2 {
    NormalizedEndpointTuple tuple;
    ProtocolPathId protocol_path_id;
};
```

Exact names are still open, but the structural split should be preserved:

- normalized effective endpoint tuple;
- compact protocol-path namespace discriminator.

### ProtocolPath

`ProtocolPath` should be an ordered sequence of `LayerKey`.

Example paths:

```text
EthernetII -> IPv4 -> TCP
EthernetII -> MPLS(label=102) -> VLAN(vid=200) -> IPv4 -> TCP
EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP
EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020384) -> IPv4 -> SCTP
```

### LayerKey

Each `LayerKey` should contain:

- layer kind;
- optional stable identifiers for that layer.

Potential v1 layer kinds:

- `EthernetII`
- `Ieee8023`
- `LlcSnap`
- `LinuxSll`
- `LinuxSll2`
- `VLAN`
- `MPLS`
- `MplsPw`
- `PPPoE`
- `PPP`
- `PBB`
- `MACsec`
- `IPv4`
- `IPv6`
- `TCP`
- `UDP`
- `SCTP`
- `VXLAN`
- `Geneve`
- `GTP-U`
- `GRE` as future-facing reserved space if added later
- `Unknown` or `Unsupported` only if later statistics/filter work needs an explicit conservative bucket

The v1 design should keep the layer-key payload numeric and compact. No strings should be stored in hot-path structures.

Stage-B implementation notes:

- `ProtocolPathId 0` is reserved as invalid / none.
- The standalone owned `ProtocolPath` model may use `std::vector<LayerKey>`.
- A future decode hot-path builder can still use bounded inline storage before interning into the registry.
- The initial model can reuse the same `EthernetII` kind for both outer and inner Ethernet positions, with path ordering and context distinguishing them.
- Current builder capacity is `32` layers via `kMaxProtocolPathLayers`.
- Builder overflow does not append additional layers and preserves only the already-stored prefix.
- Future decode integration must treat builder overflow conservatively rather than silently fabricating a complete exact path.

## Identifiers Included In V1

These identifiers should affect flow identity in v1:

- VLAN VID
- MPLS label
- PBB I-SID
- VXLAN VNI
- Geneve VNI
- GTP-U TEID

Rules:

- multiple VLAN tags appear as multiple `VLAN` layer keys in order;
- MPLS label stacks appear as multiple `MPLS` layer keys in order;
- inner Ethernet continuation is represented explicitly in the path where applicable;
- VNI and TEID are no longer presentation-only fields once `FlowKeyV2` is enabled.

## What Does Not Enter FlowKeyV2 In V1

Do not include:

- TLS
- HTTP
- DNS
- QUIC application details
- SCTP PPID
- TCP flags
- packet length
- timestamps
- application hints
- selected-packet presentation labels
- Wireshark-like deep protocol fields

Stop the protocol path at the terminal effective L4:

- TCP
- UDP
- SCTP

Do not include protocols below the terminal effective transport layer such as TLS or HTTP.

Path-presentation cleanup follows the same rule:

- the Path column keeps intermediate link / shim / overlay layers plus terminal TCP / UDP / SCTP where applicable;
- it does not duplicate terminal control protocols such as ARP, ICMP, or ICMPv6, which are already visible in the Protocol column.

## Tunnel Endpoint Policy

V1 policy:

- include tunnel namespace identifiers such as VNI and TEID;
- do not include outer tunnel source/destination IP or UDP ports in `ProtocolPathId` v1.

Tradeoff:

- packets with the same VNI and same inner tuple but different outer tunnel endpoints may still merge;
- this is acceptable for v1 because VNI/TEID are the primary namespace identifiers already present in current fixtures and presentation;
- a later strict tunnel-context mode can decide whether outer carrier endpoints should also become part of flow identity.

## GTP-U TEID Direction Caveat

GTP-U TEID is direction- or session-specific.

Consequences:

- including TEID in flow identity may split reverse directions if they use different TEIDs;
- this is acceptable for v1 because TEID is a real tunnel/session namespace identifier;
- explicit bidirectional GTP-U association tracking is out of scope for this step.

## ProtocolPathRegistry

Use an interned registry:

```text
ProtocolPath -> uint32_t ProtocolPathId
```

Rationale:

- avoid storing vectors inside every flow key;
- keep `FlowKeyV2` compact;
- support equality by real path comparison, not hash-only comparison;
- allow future reuse for:
  - protocol-path statistics trees;
  - exact/prefix path filters;
  - diagnostics and debug views.

Recommended implementation idea:

1. Build a small bounded inline path while decoding the packet.
2. Look up or insert the path in a session-owned registry.
3. Store only `protocol_path_id` on packet/flow metadata.
4. Use hashing for lookup, but verify full path equality before reusing an existing id.

## Index Serialization Compatibility

Static audit of the current format:

- `src/core/index/Serialization.cpp` serializes `FlowKeyV4` and `FlowKeyV6` directly;
- current serialized flow keys contain only:
  - addresses;
  - ports;
  - `ProtocolId`.

Current implementation state:

- `src/core/index/CaptureIndex.h` sets `kCaptureIndexVersion = 10`;
- `src/core/index/Serialization.cpp` serializes:
  - `protocol_path_id` in `FlowKeyV4` / `FlowKeyV6`;
  - `protocol_path_id` in `ConnectionKeyV4` / `ConnectionKeyV6`;
  - one capture-level `ProtocolPathRegistry` table;
- `PacketRef` records do not serialize a per-packet `protocol_path_id`;
- `src/core/index/CaptureIndexReader.cpp` rejects older versions with:
  - `unsupported index version; rebuild the index from the source capture`

Policy:

- backward compatibility with older `.pflidx` formats is not a goal for this migration;
- older indexes without protocol-path metadata are expected to be rejected with a rebuild-required message rather than silently loaded with degraded identity semantics;
- explicit legacy compatibility mode remains out of scope.

## Stable Index Storage Policy

When protocol-path-aware flow identity becomes part of the stable index format:

- store one protocol-path table / registry per capture index;
- store `protocol_path_id` at the flow identity / flow metadata level;
- let each flow reference its interned `protocol_path_id`;
- keep the protocol-path registry as a single dedicated section, not chunked per packet or per flow;
- keep large connection data chunked at connection-section boundaries rather than as one monolithic multi-GB payload;
- do not repeat full protocol paths in packet records;
- do not repeat namespace identifiers such as VLAN VID, MPLS label, VNI, or TEID redundantly per packet if they are already represented by the flow's protocol path id.

Rationale:

- avoid redundant stable-index growth from per-packet path metadata;
- keep path identity normalized around flows, where `FlowKeyV2` will use it;
- keep packet records focused on packet-local capture metadata rather than repeating flow namespace context.

Current runtime policy:

- `PacketRef` intentionally does not carry `protocol_path_id` in memory;
- recognized packets resolve protocol-path identity through the owning flow / connection key;
- unrecognized packets do not have protocol-path identity;
- packet details and protocol text rely on packet decode / packet bytes rather than stored per-packet protocol-path ids.

### Storage Diagnostics

The current implementation also exposes a runtime-only capture storage summary for large-capture investigation.

Notes:

- it is intended for diagnostics and local measurement only;
- packet and protocol-path byte totals are rough estimates, not process RSS;
- estimates intentionally exclude allocator overhead, hash-table node overhead, and transient UI/frontend copies;
- `total_packets_seen` is reported as `recognized_packets + unrecognized_packets`, because the existing capture summary packet count tracks recognized packets only.
- the Qt UI exposes the current text summary through `Help -> Capture Storage Diagnostics`.

### Index Save Notes

Current index-save behavior relevant to large protocol-path-aware captures:

- Qt save-index now runs asynchronously with low-noise progress text and cooperative cancel;
- index save writes to a same-directory temporary file and replaces the final target only after successful finalization;
- index v10 now allows repeated `ipv4_connections` and `ipv6_connections` sections so large captures can be written and reopened as bounded connection chunks;
- each connection chunk remains self-contained and split only on connection boundaries; protocol-path registry data is still written once per capture;
- the current index format does not write a separate footer/final-marker record; "finalized" currently means that all required sections parse cleanly through EOF;
- interrupted or cancelled saves should leave the previous final `.idx` unchanged;
- partial capture opens that imported at least one recognized or unrecognized packet remain saveable;
- incomplete force-killed indexes are expected to fail reopen with an explicit incomplete/not-finalized style error rather than being recovered silently.

## Statistics Tree

Runtime protocol-path statistics are now prefix-based.

Example exact path:

```text
EthernetII -> MPLS(label=102) -> VLAN(vid=200) -> IPv4 -> TCP
```

That packet should contribute to:

- `EthernetII`
- `EthernetII -> MPLS(label=102)`
- `EthernetII -> MPLS(label=102) -> VLAN(vid=200)`
- `EthernetII -> MPLS(label=102) -> VLAN(vid=200) -> IPv4`
- `EthernetII -> MPLS(label=102) -> VLAN(vid=200) -> IPv4 -> TCP`

Flow counters are incremented per recognized flow using the same prefix model.
Packet counters are accumulated from the owning flow's recognized packet count.

## Filter Follow-up

Future filter directions:

- prefix protocol-path filter;
- exact protocol-path filter;
- identifier filters such as:
  - `vlan.vid == 200`
  - `mpls.label == 102`
  - `vxlan.vni == 100`
  - `geneve.vni == 100`
  - `gtpu.teid == 0x01020384`

This document does not propose filter syntax beyond these examples.

## Performance Constraints

The design should preserve the current open/import performance profile as much as possible.

Constraints:

- avoid heap allocation per packet in the hot decode path when possible;
- use bounded inline path storage with a clear maximum layer count;
- keep `ProtocolPathId` compact in flow, packet, and connection metadata;
- registry insertion should happen only when a new path actually appears;
- do not inspect deep protocol layers below the terminal effective L4;
- do not store strings in hot-path protocol-path structures;
- generate human-readable labels lazily for UI or docs only.

Reasonable initial design assumptions:

- current shim/overlay support already has bounded layer counts:
  - Ethernet
  - up to 4 VLAN tags
  - up to 16 MPLS labels
  - outer IP + UDP + overlay + inner Ethernet/IP + terminal L4
- a small inline vector or fixed-capacity array is likely sufficient for v1.

## Proposed Implementation Sequence

Stage A:

- RFC/design doc and static audit only.

Stage B:

- add `ProtocolPath`, `LayerKey`, and `ProtocolPathRegistry` model/tests without using them in `FlowKey`.

Stage C:

- collect protocol path during decode;
- attach `protocol_path_id` to flow metadata.

Stage C2 status:

- decode now builds protocol-path metadata in the packet decode hot path using `ProtocolPathBuilder`;
- `CaptureState` owns a per-capture `ProtocolPathRegistry`;
- import now interns non-empty, non-overflowed decoded paths from a lightweight builder/view representation and stores an effective flow-identity `protocol_path_id` on `FlowKey`;
- in the common import hot path, owning `ProtocolPath` materialization is now deferred until the registry sees a new unique path;
- in the common case, decode now emits flow-identity-ready protocol paths and import interns that path once for flow identity;
- a later normalization pass is still retained only for the narrow priority-tag case where `VLAN(vid=0)` is omitted from flow identity;
- builder overflow is handled conservatively by leaving `protocol_path_id = kInvalidProtocolPathId`;
- stable storage remains flow/registry oriented rather than per-packet.

Stage D:

- add path-extraction tests and known collision fixtures/expectations;
- current Stage D / E coverage includes default regression assertions for:
  - VXLAN same inner tuple, different VNI -> split into two flows;
  - GTP-U same inner tuple, different TEID -> split into two flows;
  - MPLS same inner tuple, different label -> split into two flows;
  - same exact VXLAN path with reverse inner tuple -> still one bidirectional flow.

Stage E:

- enable `FlowKeyV2` by adding `protocol_path_id` to effective flow identity;
- carry `protocol_path_id` through both `FlowKey` and normalized `ConnectionKey`, so in-memory grouping splits same-tuple traffic when protocol paths differ;
- keep `kInvalidProtocolPathId` as the conservative fallback for unsupported/overflowed/unknown paths.

Stage E status:

- enabled in the current branch state.

Stage F:

- bump index/checkpoint formats, persist protocol-path registry metadata at the capture level plus `protocol_path_id` at the flow/connection-key level, and reject pre-FlowKeyV2 indexes with a rebuild-required path.

Stage G:

- add backend protocol-path statistics tree support.

Stage G status:

- implemented in the current branch state as a runtime session/overview tree;
- computed from flow-level `protocol_path_id` and flow packet counts;
- each runtime statistics node now also tracks the contributing flow indices in session memory only;
- membership semantics are mode-specific:
  - `kind_overview`: flows whose kind-only protocol path has the node's prefix;
  - `identity_tree`: flows whose exact identifier-aware protocol path has the node's prefix;
  - `terminal_paths`: flows whose exact full protocol path equals the terminal node path;
- intentionally not persisted as precomputed index statistics.

Current membership follow-up:

- this runtime node membership is the backend/session preparation for future "show matching flows" behavior;
- runtime protocol-path statistics rows should remain lightweight display records;
- node membership should live in session-side sidecar storage such as a `flow_index_pool` plus per-node ranges on `CaptureProtocolPathSummary`;
- membership is intentionally not exposed through the default frontend overview DTOs yet;
- future flow-list filtering should resolve matching flows through `mode + node_id` against the session, rather than embedding flow memberships directly into UI statistics payloads.

Stage H:

- add protocol-path filters and namespace-identifier filters.

Stage I:

- add UI integration for protocol-path statistics and filtering.

Stage I status:

- Statistics-tab integration is implemented in both Qt and the Tauri spike for runtime protocol-path tree display;
- Qt now uses a virtualized runtime tree presentation; top-N, search, collapse/expand, and filters remain follow-up UX work;
- the Tauri spike now also virtualizes protocol-path statistics row rendering inside the bounded tree viewport, so large mode switches and expand/collapse actions avoid rebuilding every visible DOM row at once;
- protocol-path filtering is now implemented as runtime UI state in both frontends; persistence and broader drill-down workflows remain follow-up work.

## Static Audit: Likely Touch Points

Files likely affected in later implementation stages:

- `src/core/domain/FlowKey.h`
  - `FlowKeyV4` / `FlowKeyV6` now carry the effective `protocol_path_id`
- `src/core/domain/PacketRef.h`
  - packet-local capture metadata only; no per-packet protocol-path identity
- `src/core/domain/Connection.h`
  - connection grouping and direction logic depend on current key shape
- `src/core/domain/Flow.h`
  - flow storage mirrors current key model
- `src/core/domain/ConnectionKey.h`
  - connection identity now mirrors `FlowKey` path awareness
- `src/core/decode/PacketDecoder.cpp`
  - current flow key is created here for direct IP and overlay-resolved inner tuples
- `src/core/decode/PacketDecodeSupport.h`
  - current shim and overlay identifier parsing lives here
- `src/core/services/CaptureImportProcessor.cpp`
  - current Stage C2 interning point from `DecodedPacket::protocol_path` into the per-capture registry, with the common path avoiding a second normalization/interner pass
- `src/core/index/Serialization.cpp`
  - flow key and connection key serialization now require a versioned break once `FlowKeyV2` is enabled
- `src/app/session/CaptureSession.cpp`
  - session summaries, exports, row generation, and runtime protocol-path statistics need access to protocol-path metadata
- `src/app/session/FlowRows.h`
  - current row model and runtime statistics rows expose protocol-path presentation/state
- `src/app/session/SessionFlowHelpers.cpp`
  - flow listing, protocol summary, and runtime protocol-path statistics helpers are connection-key driven
- `src/app/frontend/FrontendSessionAdapter.cpp`
  - frontend DTO assembly now carries runtime path-oriented statistics data
- `src/ui/app/MainController.cpp`
  - Qt statistics exposure for runtime protocol-path trees now surfaces here
- `tests/unit/*.cpp`
  - flow-key tests, decode/import tests, overlay fixture tests, and statistics/filter tests
- fixture directories already relevant to namespace collisions:
  - `tests/data/parsing/vxlan/`
  - `tests/data/parsing/geneve/`
  - `tests/data/parsing/gtpu/`
  - `tests/data/parsing/mpls/`
  - `tests/data/parsing/vlan/`

## Current Tuple Construction Path Summary

## Index Compatibility Policy

- backward compatibility with pre-FlowKeyV2 stable index formats is not a goal;
- when protocol-path-aware flow identity is enabled, the stable index/checkpoint format may be bumped and older artifacts may be rejected with a rebuild-required message;
- future unrelated metadata work, including richer unrecognized-packet persistence, may require later format bumps in separate branches.

## Stable Index Storage Policy

- stable capture storage should keep one protocol-path registry/table per indexed capture;
- each persisted flow/connection references a compact `protocol_path_id`;
- packet records should not redundantly persist the full protocol path or repeated per-packet protocol identifiers;
- runtime protocol-path statistics membership lists should also remain non-persisted and be rebuilt from flow metadata after import or index load;
- when index/checkpoint data is loaded back into memory, packet refs still remain packet-local capture metadata only; protocol-path identity stays flow-level.

Static audit of the current code path:

- `src/core/decode/PacketDecoder.cpp`
  - `PacketDecoder::decode(...)` is the main point where flow keys are built
  - direct IPv4/IPv6 transport decode builds `FlowKeyV4` / `FlowKeyV6` immediately after TCP/UDP/SCTP header validation
  - overlay helpers:
    - `try_decode_vxlan_inner_packet(...)`
    - `try_decode_geneve_inner_packet(...)`
    - `try_decode_gtpu_inner_packet(...)`
  - these helpers currently return inner `DecodedPacket` objects whose flow keys contain only the effective inner tuple
- `src/core/decode/PacketDecodeSupport.h`
  - already parses the namespace identifiers needed later:
    - VLAN VID through stacked VLAN parsing
    - MPLS label stack
    - VXLAN VNI
    - Geneve VNI
    - GTP-U TEID
- `src/core/services/CaptureImportProcessor.cpp`
  - consumes decoded packets and inserts them into capture state
- `src/core/index/Serialization.cpp`
  - now persists flow/connection path ids plus the shared protocol-path registry

The smallest safe insertion point was `PacketDecoder::decode(...)`, before `DecodedPacket` is returned to the import pipeline. Stages C2 through E use that path, with Stage E now enabling path-aware flow identity on top of the same decode/import handoff.

## Test Plan

Future tests should cover:

- direct `IPv4/TCP` and `MPLS/VLAN/IPv4/TCP` with the same endpoint tuple must split under `FlowKeyV2`;
- same inner VXLAN tuple with different VNI must split;
- same inner Geneve tuple with different VNI must split;
- same inner GTP-U tuple with different TEID must split;
- same exact path plus reverse tuple should still group bidirectionally where current normalized tuple semantics expect one bidirectional flow;
- same exact path plus same identifiers should preserve current grouping;
- malformed or truncated tunnel identifiers must not fabricate namespace identity;
- unknown or unsupported layers should remain conservative.

Relevant existing fixture families:

- VXLAN collision fixtures now document same-inner-tuple/different-VNI split behavior under `FlowKeyV2`;
- Geneve same-inner-tuple/different-VNI collision coverage is still missing as a dedicated deterministic fixture follow-up;
- GTP-U collision fixtures now document same-inner-tuple/different-TEID split behavior under `FlowKeyV2`;
- MPLS/VLAN fixtures already provide the shim stack shapes needed for future direct-vs-shim separation tests.
- direct-vs-shimmed same effective tuple coverage is still missing as an exact deterministic fixture follow-up;
- same-inner-tuple/different-VNI Geneve coverage is also still missing as a dedicated deterministic fixture follow-up.

## Key Decisions In This RFC

- protocol-path-aware flow identity should be modeled as:
  - normalized effective endpoint tuple
  - plus compact `ProtocolPathId`
- v1 namespace identifiers should include:
  - VLAN VID
  - MPLS label
  - VXLAN VNI
  - Geneve VNI
  - GTP-U TEID
- outer tunnel endpoints are intentionally excluded from v1 identity
- `ProtocolPathRegistry` should intern full path values and assign compact ids
- exact path changes should eventually require an index format bump
- old `.pflidx` compatibility is intentionally not a requirement for the FlowKeyV2 index break
- richer protocol-path filters beyond the current runtime Statistics-to-Flows UI filter should remain follow-up work after the first identity/statistics change

## Risks

- Flow-key migration touches many code paths:
  - connection grouping
  - index serialization
  - import pipeline
  - frontend/session summaries
- GTP-U TEID can split reverse directions where TEIDs differ by direction
- outer tunnel endpoints remain outside identity in v1, so some namespace collisions may still remain
- path extraction must stay cheap enough for open/import hot paths
- fixed-capacity path storage must be sized carefully to avoid silent truncation
- remaining test follow-ups should focus on missing collision fixtures and broader regression coverage, not tuple-only-to-path-aware expectation migration

## Remaining Open Questions

1. Should direct Ethernet and IEEE 802.3 be distinct layer kinds in the initial path model, or should they share a single link-layer kind where no namespace identifier differs?
2. Should MACsec gain a namespace-bearing identifier in a future revision if protected-payload flow recovery is ever implemented?
3. What fixed maximum layer count is acceptable for the inline hot-path representation before falling back to a slower path or rejecting overly deep packets conservatively?
4. Should exact path labels be generated only on demand from registry data, or should a small debug-only formatter exist earlier for tests and logs?
