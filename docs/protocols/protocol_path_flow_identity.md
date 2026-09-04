# Protocol Path Flow Identity

## Role

This document is the current technical contract for protocol-path-aware flow
identity in Pcap Flow Lab 0.3.0.

It describes the implemented behavior first. Historical RFC and migration
context is kept only as clearly marked background near the end.

## Current Contract

Canonical recognized-flow identity is conceptually:

```cpp
NormalizedEffectiveEndpointTuple + ProtocolPathId
```

Current implementation facts:

- recognized flow grouping uses the normalized effective endpoint tuple plus
  `protocol_path_id`;
- `ProtocolPathRegistry` interns ordered protocol paths at capture scope and
  assigns compact `ProtocolPathId` values;
- current production key types `FlowKeyV4` / `FlowKeyV6` and normalized
  `ConnectionKeyV4` / `ConnectionKeyV6` carry `protocol_path_id`;
- namespace-bearing protocol-path identifiers split otherwise identical
  effective tuples where the current parser can extract those identifiers;
- unrecognized packets do not participate in this protocol-path identity model;
- `PacketRef` remains packet-local capture metadata only and does not store a
  per-packet `protocol_path_id`.

### Current Layer Model

Current protocol-path layer kinds are defined by `ProtocolLayerKind` in
`src/core/domain/ProtocolPath.h` and currently include:

- `ethernet_ii`
- `ieee8023`
- `llc_snap`
- `linux_sll`
- `linux_sll2`
- `vlan`
- `mpls`
- `mpls_pw`
- `pbb`
- `pppoe`
- `ppp`
- `macsec`
- `ipv4`
- `ipv6`
- `tcp`
- `udp`
- `sctp`
- `icmp`
- `icmpv6`
- `arp`
- `vxlan`
- `geneve`
- `gtpu`
- `gre`
- `ah`
- `esp`

The current path is an ordered sequence of those layers. The path explains how
the product reached the effective terminal transport or other recognized
terminal protocol; it is not a generic deep-application tree.

### Current Identity-Significant Identifiers

The current code defines these identity-bearing protocol-path identifier kinds:

- `vlan_vid`
- `mpls_label`
- `pbb_isid`
- `vxlan_vni`
- `geneve_vni`
- `gtpu_teid`
- `gre_key`
- `ah_spi`
- `esp_spi`

Verified current identity-significant examples:

- VLAN VID
- MPLS label
- PBB I-SID
- VXLAN VNI
- Geneve VNI
- GTP-U TEID
- GRE key
- AH SPI
- ESP SPI

Important distinction:

- layer presence determines that the layer exists in the protocol path;
- identifier presence determines whether that layer splits namespace identity;
- many other parsed fields remain presentation-only metadata and do not split
  flow identity.

Examples of non-identity metadata today:

- VLAN PCP / DEI
- MPLS TC / TTL
- GRE checksum / sequence
- AH sequence number
- transport flags
- application hints such as TLS / HTTP / DNS / QUIC

### Import-Time Construction

Current raw-capture import uses the unified registry-driven dissection path:

- `CaptureImportApplication.cpp` runs `dissection::DissectionEngine`;
- decoded paths are built with `ProtocolPathBuilder`;
- non-empty, non-overflowed paths are interned into the capture-level
  `ProtocolPathRegistry`;
- the resulting `protocol_path_id` is written onto recognized flow and
  connection identity.

Current builder/storage boundaries:

- `ProtocolPathId 0` remains invalid;
- `kMaxProtocolPathLayers` is `32`;
- builder overflow is handled conservatively by leaving
  `protocol_path_id = kInvalidProtocolPathId`;
- current hot-path logic avoids materializing owned `ProtocolPath` objects more
  often than necessary.

Legacy `PacketDecoder` still exists in production and still has consumers
outside the import path, but it is no longer the authoritative raw-import
grouping path.

## Grouping Normalization Settings

Protocol-path-aware grouping has two independent import-time normalization
settings.

### Ignore VLAN And MPLS Layers When Grouping Flows

When `ignore_vlan_and_mpls_layers_when_grouping_flows` is enabled during raw
capture import:

- `ProtocolLayerKind::vlan` is removed from flow identity;
- `ProtocolLayerKind::mpls` is removed from flow identity;
- `ProtocolLayerKind::mpls_pw` is preserved;
- other identifier-bearing layers such as VXLAN VNI, Geneve VNI, GTP-U TEID,
  GRE key, AH SPI, and ESP SPI remain significant;
- Packet Summary, Packet Details, and Packet Bytes still show actual packet
  layers from the selected packet;
- flow-list path presentation and protocol-path statistics reflect the
  normalized stored identity path, not the stripped raw packet envelope.

Current implementation also omits `VLAN(vid=0)` from flow identity as a narrow
normalization rule even when the broader VLAN/MPLS-ignore mode is disabled.

### Ignore GTP-U TEIDs When Grouping Inner Flows

When `ignore_gtpu_teids_when_grouping_inner_flows` is enabled during raw
capture import:

- the `GTP-U` layer remains in the path;
- only the `gtpu_teid` identifier is stripped from that layer for flow
  identity;
- Packet Summary, Packet Details, and Packet Bytes can still show the actual
  TEID on the selected packet;
- flow-list path presentation and protocol-path statistics reflect the stored
  normalized identity path and therefore show `GTP-U` without `teid=...`.

This is deterministic identity normalization only. It is not tunnel
correlation, GTP-C tracking, or PFCP-aware session joining.

## Index And Persistence Contract

Current stable index revision is `16`.

Current persistence facts verified from code:

- `src/core/index/CaptureIndex.h` sets `kCaptureIndexVersion = 16`;
- the stable index stores flow and connection `protocol_path_id` values;
- the stable index stores one capture-level `ProtocolPathRegistry` table;
- packet records do not store full protocol paths or per-packet
  `protocol_path_id`;
- runtime protocol-path statistics trees are not persisted as precomputed
  structures.

Current compatibility policy:

- legacy v14 indexes are recognized but rejected for full load with a
  rebuild-required diagnostic;
- stable v15 indexes are recognized but rejected for full load with a
  rebuild-required diagnostic;
- stable v16 indexes load when their required section schemas remain
  supported;
- reopening an index preserves the grouping semantics already stored in that
  index;
- current settings do not regroup or reinterpret an existing index according to
  today's VLAN/MPLS or GTP-U normalization toggles.

That last point is important: grouping normalization applies to raw capture
import, not to later index reopen.

## Presentation And UI Consumption

Protocol-path-aware presentation is implemented today.

Current frontend-neutral contract:

- flow rows carry `protocol_path_id`;
- shared backend/session code resolves full text, compact text, and badge/chip
  presentation from the capture-level registry;
- path column and badges use shared backend presentation mapping;
- flow export CSV paths reuse the same shared presentation mapping;
- Qt and Tauri both consume the same protocol-path presentation data, though
  they do not have identical UI plumbing.

Current path presentation is explanatory identity context:

- it shows intermediate link / shim / overlay layers that led to the effective
  grouped flow;
- it is not a second application-protocol column;
- application hints such as TLS, QUIC, DNS, and HTTP do not become part of the
  v1 flow-identity path.

## Runtime Protocol-Path Statistics

Protocol-path statistics are implemented as runtime session state.

Current behavior:

- statistics are computed lazily from recognized flows plus the capture-level
  `ProtocolPathRegistry`;
- they are available after both fresh PCAP import and index load;
- the trees are cached per session/mode and rebuilt from current flow metadata,
  not persisted as precomputed index data.

Current modes:

1. `Kind overview`
2. `Identity tree`
3. `Terminal paths`

Current mode semantics:

- `Kind overview` aggregates by ordered layer kind and ignores identifier
  values;
- `Identity tree` preserves identifier-bearing layers and therefore explains
  exact current flow identity;
- `Terminal paths` is a flat list of complete identity paths only.

Current counting model:

- recognized flows contribute to prefix nodes in the tree modes;
- terminal-path mode counts only the complete path;
- unrecognized packets are excluded because they do not yet participate in the
  stable protocol-path identity model.

## Structured Flow Filtering

Selected protocol-path statistics nodes can currently drive structured
flow-list filtering.

Current behavior:

- the user selects a protocol-path statistics row;
- the frontend switches to Flows and applies a runtime membership filter for
  that node;
- the filter is runtime UI state only;
- the text filter remains independent and combines with the protocol-path filter
  using logical `AND`.

Current membership semantics:

- `Kind overview` uses kind-prefix membership;
- `Identity tree` uses identifier-aware prefix membership;
- `Terminal paths` uses exact full-path membership.

## Scope Boundaries And Current Tradeoffs

Current v1 boundaries:

- outer tunnel source/destination endpoints are not part of
  `protocol_path_id`;
- identical inner tuples can therefore still merge when the current namespace
  identifiers match but outer carrier endpoints differ;
- application-layer protocols such as TLS, HTTP, DNS, and QUIC remain outside
  flow identity;
- malformed or truncated namespace identifiers must not fabricate identity.

Current examples of intentional tradeoffs:

- different GTP-U TEIDs split by default and may merge only under the explicit
  GTP-U TEID normalization mode;
- different VLAN VIDs and MPLS labels split by default and may merge only under
  the explicit VLAN/MPLS normalization mode;
- same VNI / same inner tuple / different outer carrier endpoints may still
  merge in v1 because outer tunnel endpoints are excluded from identity.

## Historical Design Context

### Why Tuple-Only Grouping Was Insufficient

This document originally existed because tuple-only grouping was no longer
enough once the same effective inner tuple could appear through different shim
or tunnel paths.

Examples that motivated the change:

- direct `EthernetII -> IPv4 -> TCP` traffic versus
  `EthernetII -> MPLS(label=102) -> VLAN(vid=200) -> IPv4 -> TCP`;
- same inner tuple behind different VXLAN VNIs;
- same inner tuple behind different Geneve VNIs;
- same inner tuple behind different GTP-U TEIDs.

That rationale remains valid, but the system is no longer only a proposal; the
protocol-path-aware identity model is implemented.

### Historical RFC Status

Older versions of this file described a proposed multi-stage migration:

- introduce `ProtocolPath`, `LayerKey`, and `ProtocolPathRegistry`;
- attach `protocol_path_id` to flow identity;
- bump index serialization;
- add statistics and filtering on top.

Those stages are now substantially implemented in current production code.
Historical future-tense wording from the original RFC should not be read as the
current product state.

Earlier drafts sometimes used names such as `FlowKeyV2` as shorthand for the
conceptual "normalized tuple plus protocol path id" model. That name is
historical RFC terminology, not a current production type.

### Historical Notes That Still Matter

These historical constraints still explain current design choices:

- protocol-path identity must stay compact;
- hot-path decode/import must avoid unnecessary per-packet heap work;
- registry interning is preferred over storing full path vectors on each flow;
- protocol-path presentation should be generated lazily from shared backend data
  instead of duplicated eagerly per flow row.

## Source Of Truth For This Document

Primary source files for non-obvious current claims include:

- `src/core/domain/ProtocolPath.h`
- `src/core/domain/ProtocolPath.cpp`
- `src/core/services/CaptureImportApplication.cpp`
- `src/core/index/CaptureIndex.h`
- `src/core/index/Serialization.cpp`
- `src/core/index/CaptureIndexReader.cpp`
- `src/app/session/CaptureSession.cpp`
- `src/app/frontend/FrontendSessionAdapter.cpp`
- `tests/unit/ProtocolPathTests.cpp`
- `tests/unit/AnalysisSettingsTests.cpp`
- `tests/unit/StatisticsSectionTests.cpp`
- `tests/unit/CliSummaryTests.cpp`

This document should stay aligned with those sources and with the canonical
high-level docs:

- `docs/current-state.md`
- `docs/architecture.md`
- `docs/decisions.md`
