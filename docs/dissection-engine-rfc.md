# Dissection Engine RFC

Status: Proposed
Scope: Packet-oriented L2-L4 and tunnel dissection
Implementation branch: `feature/unified-packet-dissection`

## Goal

Define a registry-driven packet dissection architecture that can replace the current centralized `PacketDecoder` traversal without changing current product semantics during the migration.

The immediate motivation is not new protocol coverage by itself. The real goal is to stop maintaining the same packet-structure knowledge in multiple places:

- import-time `PacketDecoder`;
- selected-packet `PacketDetailsService`;
- selected-flow transport-payload length recovery in `SelectedFlowPacketSemantics`;
- parts of hint extraction that need their own packet slicing assumptions.

## Current State

Today the production packet path is split across two different styles.

### Import-time path

- `CaptureImportProcessor` calls `PacketDecoder::decode(...)`.
- `PacketDecoder` performs a large centralized conditional traversal over:
  - outer link handling from `parse_network_payload(...)`;
  - IPv4 / IPv6 transport dispatch;
  - plain IP encapsulation;
  - VXLAN / Geneve / GTP-U;
  - GRE / EoIP;
  - AH / ESP;
  - ARP / IGMP / ICMP / ICMPv6 / SCTP / TCP / UDP.
- The decoder returns a small `DecodedPacket`:
  - `IngestedPacketV4` or `IngestedPacketV6`;
  - `ProtocolPathBuilder`.
- `CaptureImportProcessor` interns the decoded protocol path and finalizes flow identity before `PacketIngestor` writes packet metadata into `CaptureState`.

### Selected-packet path

- `CaptureSession::read_packet_details(...)` rereads packet bytes lazily and calls `PacketDetailsService::decode_best_effort(...)`.
- `CaptureSession::read_packet_protocol_details_text(...)` runs higher-level analyzers first:
  - TLS;
  - QUIC;
  - DNS;
  - HTTP;
  then falls back to strict or best-effort `PacketDetailsService`.
- `SessionFormatting` turns `PacketDetails` into Summary layers and Protocol text.

### Consequence

The project already has two dissection systems:

1. metadata-oriented strict traversal for import and flow identity;
2. presentation-oriented best-effort traversal for packet details.

They share low-level parsing helpers in `PacketDecodeSupport.h`, but they do not share a common traversal engine or a common intermediate event model.

## Strengths To Preserve

The new design should keep the parts that are already working well.

- Open/import remains packet-oriented and bounded.
- Low-level parse helpers in `PacketDecodeSupport.h` already encode many conservative truncation rules and should be reused rather than rewritten all at once.
- Flow identity is already based on terminal tuple plus `protocol_path_id`.
- Selected-packet details already support a best-effort mode that can show partial layers without fabricating recognized flows.
- Reassembly is already isolated in `core/reassembly` and should stay out of the import path.

## Primary Architectural Decision

Introduce a registry-driven dissection engine that walks a packet as a sequence of protocol modules.

Each protocol module is responsible for:

- deciding whether it matches in the current selector domain;
- parsing only its own bounded header/payload view;
- contributing:
  - dissection events;
  - protocol-path layers;
  - optional flow-identity facts;
  - optional diagnostic warnings;
  - the next selector/input for further traversal.

Instead of one centralized function knowing every transition, the engine owns the traversal loop and the modules own protocol-local decisions.

The current production path remains on legacy `PacketDecoder` until a staged cutover is complete.

## Terminology

- `packet slice`
  - A bounded packet view that carries source-relative positioning plus captured, reported, and currently declared structural bounds for the current protocol node.
- `canonical protocol parser`
  - The only structural implementation of a protocol's wire format.
- `dissector`
  - The registry adapter that invokes a canonical parser and turns its result into traversal facts for a specific consumer.
- `selector domain`
  - The namespace used to choose the next protocol module.
- `exact deterministic selector`
  - A selector whose protocol meaning is structurally determined by the current layer, such as link type, EtherType, PPP protocol, IP protocol, IPv6 Next Header, or GRE protocol type.
- `candidate dispatch selector`
  - A selector that nominates one or more candidate dissectors that must still validate their own header before claiming the layer, such as UDP destination port for VXLAN, Geneve, or GTP-U.
- `service hint`
  - Port-based or payload-based metadata that may decorate a flow but does not itself establish a protocol layer.
- `dissection step`
  - One protocol-module invocation over one packet slice.
- `path contribution`
  - The physical `LayerKey` a step contributes to `ProtocolPathBuilder`. This is separate from the visible/current layer so future container or presentation-only layers can differ from flow-identity path material.
- `identity contribution`
  - A protocol-local physical fact relevant to later identity construction, such as GRE key, EoIP tunnel id normalized through GRE-key semantics, AH SPI, ESP SPI, VXLAN VNI, Geneve VNI, or GTP-U TEID.
- `consumer`
  - Code that reads emitted events/results for a purpose such as import, packet details, or diagnostics.

## Invariants

The engine must preserve these invariants.

- Import-time dissection stays bounded by captured packet bytes and existing conservative truncation rules.
- A best-effort presentation path may expose partial layers, but it must not fabricate a recognized flow tuple.
- Strict import and best-effort packet-details consumers must not own separate structural header parsers for the same protocol.
- Protocol-path layer order remains stable and continues to use `LayerKey` / `ProtocolPathBuilder` semantics already present in `ProtocolPath.h`.
- `kInvalidProtocolPathId` still means no path / unusable path.
- Reassembly stays outside this engine.
- Application protocols such as TLS / QUIC / HTTP / DNS stay out of the first engine scope.
- The engine must support consumer-dependent collection and continuation policy without changing structural parse rules.
- Best-effort may expose a partial current layer, but it may not continue into a child layer unless the canonical parse result bounded that child slice safely.
- Traversal must use an explicit depth bound and produce a structured `depth_limit` stop when exceeded.

## Proposed Core Model

### PacketSlice

The engine should pass protocol modules a lightweight bounded view instead of raw packet ownership.

Conceptually:

```cpp
struct PacketSlice {
    ByteSourceId source_id;
    std::span<const std::uint8_t> captured_bytes;

    std::size_t source_offset;
    std::size_t captured_end;
    std::size_t reported_end;
    std::size_t declared_end;
};
```

Properties:

- never owns bytes;
- always refers to already materialized packet bytes;
- can represent outer packet scope or a bounded inner payload scope;
- is suitable for both strict import and best-effort details.
- conceptually prefers end offsets over lengths where that reduces nested overflow and offset-composition mistakes.

Required conceptual meanings:

- `captured end`
  - the end of bytes physically available in the current materialized capture record;
- `reported end`
  - the end implied by the capture record's reported packet length;
- `declared end`
  - the maximum boundary allowed by the enclosing protocol declaration currently in force.

These three boundaries must remain distinguishable:

- truncation means the capture ended before a structurally valid declared range was fully available;
- malformed declared lengths mean the current protocol attempted to describe a child range outside the enclosing reported or declared limits.

Required conceptual helper:

```cpp
PacketSlice make_child_slice(
    const PacketSlice& parent,
    std::size_t payload_offset,
    std::size_t declared_payload_length
);
```

The final names can differ, but the RFC requires one centralized child-slice operation.

That operation must:

- detect addition overflow;
- never create a child outside the parent captured boundary;
- never create a child outside the parent reported boundary;
- never create a child outside the parent declared boundary;
- preserve captured-versus-reported differences;
- allow truncation to be distinguished from malformed declared lengths.

Protocol modules must not independently open-code these calculations.

### Canonical parser and dissector split

Each protocol family should be split conceptually into two layers.

Canonical protocol parser:

- is the only structural implementation of that protocol's wire format;
- validates fixed and variable header lengths;
- reads fields and byte order;
- calculates header and payload ranges;
- returns structured facts plus a parse status using the same bounds rules for every consumer.

It does not:

- decide strict versus best-effort product behavior;
- emit UI strings;
- mutate flow identity;
- build `ProtocolPathId`;
- access index state.

Dissector:

- invokes the canonical parser;
- emits protocol facts to a consumer;
- reports physical path and identity-bearing facts;
- returns the next selector and bounded child slice, if any.

Strict import and best-effort packet details therefore share one structural parser result and differ only in collection and continuation policy.

### Selector domains

The first engine version should support a small explicit set of selector domains.

Exact deterministic selectors:

- link-type root;
- EtherType;
- LLC/SNAP resolved PID;
- PPP protocol;
- IP protocol;
- IPv6 Next Header;
- GRE protocol type.

Candidate dispatch selectors:

- UDP destination port used to nominate VXLAN, Geneve, or GTP-U candidate dissectors.

Candidate dispatch does not mean recognition by port alone. A candidate dissector must validate its own header before:

- emitting a recognized protocol layer;
- contributing path or identity facts;
- continuing traversal.

Service hints and heuristic application recognition are separate concerns and stay outside the first engine scope.

This matches how the current code already branches, but moves those branch tables out of one monolithic traversal function.

### Parse result model

Conceptually:

```cpp
enum class ParseStatus {
    complete,
    truncated,
    malformed,
    unsupported_variant,
    opaque
};

enum class StopReason {
    none,
    terminal_protocol,
    no_payload,
    unknown_next_protocol,
    unrecognized_payload,
    encrypted_payload,
    needs_reassembly,
    unsupported_variant,
    malformed,
    truncated,
    depth_limit
};

struct ProtocolHandoff {
    ProtocolSelector selector;
    std::optional<PacketSlice> child;
};

struct BoundedByteRange {
    ByteRange declared;
    ByteRange captured;
};

struct LayerBounds {
    ByteSourceId source_id;
    BoundedByteRange full;
    BoundedByteRange header;
    std::optional<BoundedByteRange> payload;
};

using LayerFacts = std::variant<
    std::monostate,
    EthernetFacts,
    VlanFacts,
    ArpFacts,
    Ipv4Facts,
    TcpFacts,
    UdpFacts
>;

enum class TerminalDisposition {
    none,
    flow_candidate,
    recognized_non_flow
};

struct DissectionStep {
    LayerKey layer;
    std::optional<LayerKey> path_contribution;
    LayerBounds bounds;
    std::optional<ProtocolHandoff> handoff;
    LayerFacts facts;
    TerminalDisposition terminal_disposition;

    ParseStatus status;
    StopReason stop_reason;
};
```

The final implementation can use different names, but the RFC should prohibit ambiguous boolean combinations.

Interpretation:

- parse status describes the current layer;
- `layer` may still name the attempted/current protocol for diagnostics even when parsing is partial or malformed;
- `path_contribution` is emitted only after the current layer's canonical structural parser completes successfully;
- stop reason describes why traversal does or does not continue;
- the engine may continue only when:
  - `stop_reason == none`;
  - `handoff` exists;
  - `handoff.child` exists;
- a handoff may preserve only the next selector when traversal must stop safely before creating a child slice;
- reaching a terminal protocol does not itself mean that a valid flow tuple was necessarily produced.

Example:

- ESP:
  - `status = complete`
  - `stop_reason = encrypted_payload`

## Event Model

The engine may expose typed event categories, but event allocation must not be the normal import path contract.

Representative event categories:

- `LayerEntered`
- `FieldValue`
- `Warning`
- `ProtocolPathContribution`
- `TerminalTransportTuple`
- `PayloadBounds`
- `FragmentationFact`
- `OpaquePayload`

Normal import dissection must not allocate:

- a `std::vector` of events per layer;
- a transcript per packet.

Acceptable implementation directions:

- direct lightweight sink callbacks;
- a callback table;
- fixed-capacity event storage;
- compact typed fields on the dissection step/result itself.

Full event transcripts are future selected-packet or debug behavior only.

Presentation-only events should be emitted or collected only when a consumer requests them.

## Identity Contributions

Flow identity should not be computed by every consumer independently.

Each relevant module should emit physical protocol facts:

- link / shim layers that become `LayerKey` path entries;
- namespace-bearing identifiers:
  - VLAN VID;
  - MPLS label;
  - PBB I-SID;
  - VXLAN VNI;
  - Geneve VNI;
  - GTP-U TEID;
  - GRE key;
  - AH SPI;
  - ESP SPI;

Global identity policy remains outside protocol modules.

Examples:

- the VLAN parser emits `VLAN(vid=0)` when it is physically present;
- a truncated or malformed VLAN step may still identify VLAN for diagnostics, but it does not contribute `VLAN(vid=0)` or any other fabricated path entry;
- the direct dissection path keeps general-depth VLAN chaining bounded by the explicit traversal depth and protocol-path capacity, rather than restoring any legacy two-tag cap;
- later import-time flow-identity policy may omit VLAN VID `0` from normalized identity;
- `ProtocolPath` normalization, interning, `FlowKey` assignment, and index concerns remain outside protocol modules.

Protocol-local interpretation is still allowed where it is genuinely protocol-local:

- GRE key extraction;
- EoIP tunnel id normalization into the existing GRE-key identity representation;
- AH SPI extraction;
- ESP SPI extraction;
- VXLAN VNI / Geneve VNI / GTP-U TEID extraction.

## Diagnostics

The engine should make conservative stop reasons first-class.

Examples:

- link-layer header truncated;
- IPv4 header truncated;
- UDP header truncated;
- unsupported GRE version;
- unsupported Geneve protocol type;
- inner Ethernet truncated;
- protocol path overflow;
- selector had no registered handler.

This is useful for:

- current unrecognized-packet reason text;
- best-effort selected-packet warnings;
- future differential tests between legacy and new traversal;
- future perf/debug instrumentation.

## Registry Construction

The engine should use explicit registries instead of hard-coded nested switch trees.

Conceptually:

- root registry keyed by link type;
- child registries keyed by selector domain and numeric selector value;
- protocol modules register themselves against one or more selectors.

Important constraint:

- registry construction should be static and deterministic;
- the engine must not allocate per packet to construct dispatch tables.

## Engine Loop

High-level loop:

1. Start with the root `PacketSlice` and a root selector from link type.
2. Find the registered module for the current selector.
3. Run the module through the relevant consumer using the shared canonical parse result.
4. Collect only the fields or diagnostics requested by that consumer.
5. If the step yields a non-`none` stop reason, finish.
6. Otherwise advance only when a handoff selector and bounded child slice are both present; missing child or missing handoff is a conservative stop.

Selector-only handoffs are valid when a module can safely preserve the next selector but must not continue traversal. Example:

- fragmented IPv4 may preserve the raw `ip_protocol` selector while stopping with `needs_reassembly`;
- the engine still stops immediately because `stop_reason != none`.

This replaces current ad hoc recursion such as:

- inner plain IPv4 / IPv6 continuation;
- overlay re-entry through UDP;
- GRE to Ethernet/IP/MPLS continuation;
- AH continuation to direct transport or tunnel payload.

Traversal must enforce an explicit maximum depth, for example:

```cpp
inline constexpr std::size_t kMaxDissectionDepth = ...;
```

That bound may be related to, but is not necessarily identical to, `ProtocolPath::kMaxProtocolPathLayers`, because not every parsed layer must participate in flow identity.

## Consumer Model

The same traversal should feed multiple consumers.

### Import consumer

Needs:

- terminal recognized tuple, if any;
- fragmentation fact;
- terminal payload length bounds;
- TCP flags where relevant;
- protocol-path contributions;
- unrecognized stop reason when recognition fails.

It should not pay to materialize full packet-details trees.

### Packet-details consumer

Needs:

- fields and diagnostics for visible layers;
- fields and warnings;
- best-effort continuation when safe;
- protocol text and Summary layer input.

Packet-details migration is explicitly deferred until after import cutover parity.

### Flow-hint consumer

The first engine version does not need to subsume app-level hints fully, but it should at least expose stable transport payload bounds and terminal transport identity so hint extraction stops re-deriving packet structure in parallel.

### Selected-flow payload-length consumer

`SelectedFlowPacketSemantics` currently reparses headers again to recover captured/original transport payload lengths. The new engine should eventually allow those lengths to come from the same dissection facts instead of header-specific re-walks.

## Protocol Module Layout

Recommended layout after migration stabilizes:

- `core/dissection/`
  - engine loop
  - selector definitions
  - shared event/result types
  - registry builder
- `core/dissection/modules/`
  - link / Ethernet / Linux cooked
  - VLAN / LLC-SNAP / PPPoE / PPP
  - MPLS / PBB / MACsec
  - IPv4 / IPv6
  - TCP / UDP / SCTP / ICMP / IGMP
  - VXLAN / Geneve / GTP-U
  - GRE / EoIP
  - AH / ESP

The exact folder names can change, but the key point is that protocol-local continuation rules move next to their protocol parser, not into one monolithic decoder file.

## GRE And EoIP Nuance

GRE and EoIP are a good stress case and should shape the engine design.

- GRE version, flags, protocol type, optional fields, and payload selector belong to a GRE module.
- EoIP is not a separate top-level IP protocol; it is a GRE payload shape with additional semantics.
- GRE TEB and GRE MPLS are not the same continuation path.
- EoIP identity normalization currently reuses the GRE-key slot and must remain consistent during migration.

This is exactly the kind of branching that is too brittle in a centralized traversal and benefits from protocol-local modules with explicit selector transitions.

## Generic Data Layer

The engine should support a conservative opaque-payload terminal event.

This is not the same as application protocol support.

Use cases:

- unsupported GRE or tunnel payload type;
- unresolved Ethernet continuation behind bounded inner payload;
- unknown PPP or SNAP payload that still deserves diagnostics.

The first engine cutover does not need a user-visible generic `Data` summary layer everywhere, but the event model should be able to represent opaque terminal payloads so packet-details consumers can keep current conservative behavior.

## Performance Requirements

The migration must not regress current open/import scalability.

- no packet-global heap graphs per packet;
- no eager materialization of UI-oriented strings during import;
- no storing full event transcripts in `CaptureState`;
- protocol-path contributions must still be compact enough for current `ProtocolPathRegistry`;
- import must remain able to stop after deriving only the facts needed for flow identity and packet metadata.
- structural parsing must remain shared even when consumers request different amounts of collected output.

The engine should allow consumer-dependent collection and continuation policy:

- import requests only compact flow metadata and safe continuation needed to derive it;
- packet details may request richer fields and diagnostics;
- both must consume the same canonical structural parse rules and child-slice bounds.

## Migration Plan

### Stage 1: RFC and types

- land this RFC and foundational value types;
- define shared engine/event/selector types;
- keep legacy `PacketDecoder` as production path.

### Stage 2: common direct modules in shadow tests

- implement the explicit registry and bounded engine loop;
- implement common direct modules in shadow mode only:
  - Ethernet;
  - Linux SLL / SLL2;
  - VLAN;
  - LLC/SNAP;
  - ARP;
  - IPv4;
  - IPv6;
  - IPv6 extension headers;
  - TCP;
  - UDP;
  - SCTP;
  - ICMP;
  - ICMPv6;
  - IGMP;
- run only in tests and diagnostics.

### Stage 3: remaining currently supported modules in shadow tests

- migrate the remaining packet-oriented families in shadow mode:
  - MPLS;
  - PBB;
  - MACsec;
  - PPPoE / PPP where currently supported;
  - plain IP encapsulation;
  - VXLAN;
  - Geneve;
  - GTP-U;
  - GRE;
  - EoIP;
  - AH;
  - ESP.

### Stage 4: full semantic differential parity

- compare the new engine against legacy behavior across all committed fixture families;
- verify tuple recognition, payload bounds, path contributions, stop reasons, and conservative no-flow behavior.

### Stage 5: single production import cutover

- make the engine the implementation behind the existing `PacketDecoder` / public decode API;
- continue to produce the existing `DecodedPacket` / `IngestedPacket` structures;
- do not introduce a production parser feature flag;
- do not expose a mixed legacy/new production decoder between intermediate commits.

### Stage 6: remove legacy centralized traversal

- remove duplicated legacy traversal only after semantic parity, real-capture checks, and performance validation pass;
- keep `PacketDecodeSupport.h` helpers that remain useful, but retire centralized traversal code paths.

### Deferred follow-up

Only after import cutover:

- `PacketDetailsService` convergence;
- ordered packet dissection for selected-packet surfaces;
- Summary + Bytes UI convergence;
- Data-layer presentation;
- derived TLS / QUIC artifacts.

The common direct protocol subset is the first shadow milestone, not a partial production cutover.

## Differential Tests

The migration needs explicit parity testing.

Recommended test classes:

- legacy decoder vs new engine terminal tuple parity;
- legacy decoder vs new engine protocol-path parity;
- legacy decoder vs new engine fragmentation/no-flow parity;
- packet-details parity for selected representative fixtures;
- malformed/truncated parity where the expected outcome is conservative stop, not recognition.

Representative fixture families already present in the repository:

- Ethernet / VLAN / LLC-SNAP;
- IPv4 / IPv6 / IPv6 extension headers;
- MPLS / MPLS pseudowire;
- PBB / MACsec / PPPoE;
- plain IP encapsulation;
- VXLAN / Geneve / GTP-U;
- GRE / EoIP;
- AH / ESP;
- malformed / truncated packets.

## Cutover Criteria

Do not switch production import to the new engine until all of these are true across all currently supported packet-oriented protocol families.

- tuple recognition matches legacy behavior;
- protocol-path contributions match legacy behavior;
- unrecognized/no-flow behavior matches legacy behavior;
- selected-flow payload-length semantics are either preserved or intentionally re-sourced from engine facts;
- no measurable regression is found in open/import complexity for representative captures.

## Non-goals

- no full application-protocol engine in this branch;
- no TLS / QUIC / HTTP / DNS parser migration in the import cutover;
- no reassembly integration into the dissection engine;
- no index format change by itself;
- no packet-byte persistence change;
- no rewrite of every low-level parser helper before migration begins.

## Deferred Work

- richer app-layer dissection over terminal payload slices;
- engine-backed payload extraction for `FlowHintService`;
- engine-backed replacement for `SelectedFlowPacketSemantics` reparsing;
- optional shared transcript tooling for debug/dev diagnostics;
- possible future module-level perf counters.
- packet-details convergence after import parity.

## Open Questions

- whether packet-details Summary should eventually be built directly from engine events or from a normalized `PacketDetails` object produced by an engine-backed consumer;
- how much of `PacketDecodeSupport.h` should remain as reusable bounded parsers versus being split into module-local helpers over time;
- whether unrecognized-packet reasons should be produced directly by engine diagnostics or still post-processed for user-facing wording.

## Recommended Next Step

Implement foundational value types and bounds helpers, then the explicit registry and bounded engine loop, then the common direct protocol modules in shadow comparison only.

Keep production `PacketDecoder` unchanged until all currently supported packet-oriented protocol families reach semantic parity in shadow tests.
