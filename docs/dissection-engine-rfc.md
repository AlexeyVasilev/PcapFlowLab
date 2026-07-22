# Dissection Engine RFC

Status: Proposed
Scope: Packet-oriented L2-L4 and tunnel dissection
Implementation branch: `feature/unified-packet-dissection`

Static cutover audit: see `docs/dissection-engine-parity-audit.md`.

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

## Current Production Fixture Contract Notes

The current production VXLAN behavior is now explicitly captured by the committed fixtures under `tests/data/parsing/vxlan/` and the production-only assertions in `tests/unit/VxlanPcapFixtureTests.cpp`.

- The fixture contract covers the exact current production UDP entry rule, header validation, VNI identity, outer-fragment handling, supported inner Ethernet continuations, unsupported continuations, and nested-overlay negatives.
- UDP and Ethernet canonical shadow parsers already exist and remain the future migration boundary for VXLAN.
- Shadow VXLAN dissection now exists in the registry-driven path with the same strict destination-port `4789` gate, exact 8-byte header validation, and big-endian 24-bit VNI identity.
- Successful shadow VXLAN traversal keeps outer UDP in the physical path, uses the inner tuple as the final flow identity, and stays within a restricted inner Ethernet profile.
- Nested UDP overlays are not recursively decoded inside shadow VXLAN; inner UDP terminates as UDP even when its ports look like VXLAN, Geneve, or GTP-U.
- Invalid, truncated, or unsupported VXLAN candidates preserve the production-compatible ordinary outer UDP or no-flow outcome instead of fabricating VXLAN identity.

The current production Geneve behavior is now likewise pinned by the committed
fixtures under `tests/data/parsing/geneve/` and the production-only assertions
in `tests/unit/GenevePcapFixtureTests.cpp`.

- The fixture contract covers the exact current production destination-port gate `6081`, version-`0` requirement, bounded 4-byte-unit option skipping, big-endian 24-bit VNI identity, restricted inner Ethernet continuation subset, unsupported inner-EtherType fallback behavior, nested-overlay non-recursion, and exact declared-bounds edge cases.
- UDP and Ethernet canonical shadow parsers already exist and remain the migration boundary for Geneve.
- Shadow Geneve dissection now exists in the registry-driven path with the same strict UDP/6081 gate, bounded option skipping, VNI-bearing identity, tolerant OAM/Critical/control-bit handling, and the same restricted inner Ethernet continuation subset as the committed production fixture contract.
- Unsupported inner Ethernet payloads and nested inner overlay lookalikes do not commit Geneve path identity in shadow mode; they fall back to the ordinary outer UDP flow exactly as the committed production Geneve fixtures require.
- In the fixture-28 negative declared-bounds case, shadow traversal still retains the successfully decoded outer `EthernetII -> IPv4` layers diagnostically, but the packet remains unrecognized and produces no flow and no persistent protocol-path registry entry.

The current production GTP-U behavior is now pinned by the committed fixtures
under `tests/data/parsing/gtpu/` and the production-only assertions in
`tests/unit/GtpuPcapFixtureTests.cpp`.

- The fixture contract covers the exact current UDP destination-port `2152`
  gate, base-header acceptance rules, TEID identity, optional E/S/PN block
  semantics, bounded extension-header skipping, direct-inner-IP-only
  continuation, control-message outer-UDP fallback, nested inner-UDP
  non-recursion, carrier-context reachability, and outer-fragment shell
  behavior.
- Shadow GTP-U dissection now exists in the registry-driven path with the same
  strict UDP destination-port `2152` gate, TEID-bearing identity, bounded
  optional E/S/PN handling, bounded extension-header skipping, direct-inner-IP
  continuation subset, inner-UDP non-recursion, and outer-fragment shell
  behavior as the committed production fixture contract.
- Unsupported, malformed, or bounded-truncated GTP-U candidates do not commit
  GTP-U path identity in shadow mode; they fall back to the ordinary outer UDP
  flow exactly as the committed production GTP-U fixtures require.

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

For IPv6 specifically, this means extension-header traversal must not be hidden inside an IPv6-local chain walker. Each supported IPv6 extension header must be registered under `SelectorDomain::ipv6_next_header` and traversed by the generic engine as its own dissection step.

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
- `dissection layer kind`
  - A dissection-local step identity used by the shadow engine to describe the current visible layer, even when that layer has no corresponding production `ProtocolLayerKind`.
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
- The shadow engine's visible step identity remains dissection-local and must not force new `ProtocolLayerKind` or `LayerKey` values unless production flow identity genuinely needs them.
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
- PPP frame entry;
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

For IEEE 802.3 specifically, the length field defines a bounded child slice for any LLC/SNAP continuation. Captured bytes beyond that declared child length remain outside the child slice and therefore cannot complete a truncated LLC/SNAP header or become inner IP payload. In the shadow engine this continuation is modeled as one `LLC/SNAP` step that retains the raw OUI, dispatches supported children by PID through the registry, and uses an explicit deferred path-commit policy: the parent `IEEE 802.3` contribution is marked as child-deferrable, and the `LLC/SNAP` step can defer both contributions until supported downstream flow or recognized-non-flow success. Nested path commit policies combine monotonically, so a descendant may tighten an enclosing requirement but cannot weaken it. Non-SNAP LLC and unknown SNAP PID remain conservative no-flow cases, and this shadow-only mechanism does not introduce new persistent `ProtocolLayerKind`, `LayerKey`, or index-format state.

PPPoE / PPP follow the same bounded-child rule in shadow mode. `EtherType 0x8863` and `0x8864` use separate stateless PPPoE Discovery and PPPoE Session entry wrappers even though they share the same fixed six-byte header. The PPPoE Length field creates the bounded child used for any Session continuation, but the child length is clamped to the enclosing declared slice so no PPP or inner IP bytes can be consumed beyond the enclosing boundary. Supported Session continuation remains limited to version `1`, type `1`, code `0x00`, and a separate PPP step parses exactly one big-endian two-byte PPP Protocol field before dispatching through `SelectorDomain::ppp_protocol`. Only the current production subset continues further: `0x0021` -> IPv4, `0x0057` -> IPv6, and opaque no-flow control handling for `0xC021`, `0x8021`, and `0x8057`. PPPoE Session ID remains diagnostic metadata only; shadow path contribution still uses persistent `LayerKey::pppoe()` and `LayerKey::ppp()` with explicit flow-success-only commit policies, and nested descendant policies are combined with the strictest active ancestor requirement rather than replaced. Unsupported Session variants, Discovery packets, PPP control packets, unknown PPP protocols, and bounded inner truncation cases therefore leave no final physical-path contribution.

Known shadow parity gaps: `tests/data/parsing/pppoe/20_pppoe_bad_length_extra_payload.pcap` is intentionally left divergent today. That fixture advertises PPPoE payload length `33` while the inner IPv4 Total Length is `37`; legacy bounded decoding still recognizes the packet as `PPPoE -> PPP -> IPv4 -> UDP`, but the shadow `PacketSlice` model rejects the inner IPv4 child because it exceeds the enclosing declared PPPoE boundary. This declared-boundary cutover choice must be resolved explicitly before production import migration.

This matches how the current code already branches, but moves those branch tables out of one monolithic traversal function.

Linux cooked root dissection follows the same staged rule set in shadow mode. `DLT_LINUX_SLL` and `DLT_LINUX_SLL2` are root link-type modules that dispatch only the currently supported cooked-root protocol types for IPv4, IPv6, and ARP through a dedicated selector domain. Their root path contribution uses an explicit commit policy that succeeds for either recognized flows or recognized non-flow terminals such as ARP. Nested policy composition remains monotonic here as well, and the current implementation models that with one linear active descendant policy rather than a general branching scope stack. Unsupported cooked-root VLAN/QinQ values remain conservative no-flow cases. Current shadow ARP behavior is still intentionally divergent from production import: the shadow ARP step finalizes as `recognized_non_flow` and contributes an `ARP` path layer, while production import persists IPv4 ARP as a flow on the carrier path only. The static parity audit therefore treats ARP as a cutover blocker rather than a resolved parity slice.

Transport dissectors such as TCP, UDP, and SCTP should remain address-family-agnostic and be reusable across both `SelectorDomain::ip_protocol` and `SelectorDomain::ipv6_next_header` registrations.

The same `dissect_ipv4` and `dissect_ipv6` modules may also be registered in both the Ethernet-resolved selector domains and the IP selector domains used for plain encapsulation. Nested IP traversal should therefore remain iterative and registry-driven: each IPv4 or IPv6 header contributes one ordinary engine step, repeated network layers remain visible in ordered dissection steps and `ProtocolPath`, and the deepest successfully parsed network layer supplies the effective terminal flow endpoints.

IPv4 options remain part of the single IPv4 step rather than becoming a separate registered dissector or path layer. Shadow facts may carry a compact allocation-free summary of the options area, including bounded Router Alert recognition and malformed-options diagnostics, but valid TCP / UDP / SCTP / nested-IP traversal continues to use the computed IPv4 header length exactly as it does for option-free IPv4. Internal IPv4-options malformations therefore do not by themselves suppress downstream traversal once the enclosing IPv4 header and packet bounds are structurally valid.

ICMP and ICMPv6 should be modeled as portless terminal flow candidates. They use the deepest effective IPv4 or IPv6 endpoints together with `ProtocolId::icmp` or `ProtocolId::icmpv6`, without synthetic transport ports or application-level message classification.

IGMP should be modeled as a portless IPv4 terminal flow candidate whose generic network facts come from the deepest effective IPv4 layer, while final flow identity preserves the current production multicast-group override semantics. In practice that means complete non-v3 IGMP headers may replace the effective IPv4 destination with the parsed group address when it is non-zero, while IGMPv3 membership reports and selector-only fragment cases retain the deepest IPv4 destination. Current shadow IGMP recognition may expose `DissectionLayerKind::igmp` without contributing a production `LayerKey`, so shadow visibility does not by itself alter persistent `ProtocolPath` semantics. Type-specific IGMPv3 record bodies remain opaque in this stage, and IPv6 multicast-listener semantics stay under ICMPv6 rather than IP protocol `2`.

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
    Ipv6Facts,
    Ipv6ExtensionFacts,
    Ipv6FragmentFacts,
    IcmpFacts,
    Icmpv6Facts,
    IgmpFacts,
    TcpFacts,
    UdpFacts,
    SctpFacts
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

### Dissection step identity versus path identity

The engine must keep two distinct identities for each step:

- a dissection-local layer identity used for traversal, diagnostics, and test assertions;
- an optional production-compatible `LayerKey` path contribution used only when the step should participate in `ProtocolPathBuilder`.

Conceptually:

```cpp
enum class DissectionLayerKind {
    ethernet_ii,
    vlan,
    ipv6,
    ipv6_hop_by_hop,
    ipv6_routing,
    ipv6_destination_options,
    ipv6_fragment,
    tcp,
    udp,
    // ...
};

struct DissectionStep {
    DissectionLayerKind layer;
    std::optional<LayerKey> path_contribution;
    // ...
};
```

This split is required because some visible traversal steps, such as IPv6 extension headers, matter to shadow dissection correctness and diagnostics but do not currently belong in production flow-identity path semantics.

IGMP is also allowed to use this split: the shadow engine may emit a visible IGMP step while contributing no production `LayerKey` until a later production-cutover decision explicitly adds one.

The final implementation can use different names, but the RFC should prohibit ambiguous boolean combinations.

For IPv6 extension headers, shared helpers may parse one bounded header at a time, but they must not walk a multi-header chain internally. Repeated Hop-by-Hop, Routing, Fragment, and Destination Options headers must consume generic engine depth one step at a time.

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
- successful ICMP / ICMPv6 terminal steps remain visible dissection steps with typed facts, but under the current import-compatibility policy they contribute no persistent `LayerKey::icmp()` / `LayerKey::icmpv6()` path material.

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

For PPPoE specifically, keep the common fixed-header parser pure and allocation-free, but retain separate Discovery and Session wrapper registrations under EtherType. Do not infer Discovery versus Session from payload contents or surrounding Ethernet state.

## GRE And EoIP Nuance

GRE and EoIP are a good stress case and should shape the engine design.

- GRE version, flags, protocol type, optional fields, and payload selector belong to a GRE module.
- EoIP is not a separate top-level IP protocol; it is a GRE payload shape with additional semantics.
- GRE TEB and GRE MPLS are not the same continuation path.
- EoIP identity normalization currently reuses the GRE-key slot and must remain consistent during migration.
- In the current shadow-only stage, GRE v0 is traversed as a normal registered layer under `SelectorDomain::ip_protocol` or `SelectorDomain::ipv6_next_header`, then hands off through `SelectorDomain::gre_protocol_type`.
- Direct GRE-carried IPv4 or IPv6 and GRE TEB reuse the existing IPv4, IPv6, and Ethernet dissectors rather than embedding child parsing inside the GRE module.
- GRE optional checksum, key, and sequence fields are parsed in wire order for facts and bounds, but only GRE key contributes to `ProtocolPath` identity.
- GRE-carried MPLS may be traversed in shadow mode through the same explicit MPLS module used for direct EtherType MPLS entry, one label shim per engine step.
- The exact current production GRE-versus-EoIP contract is now defined by the committed fixtures under `tests/data/parsing/eoip/` and `tests/unit/EoipPcapFixtureTests.cpp`.
- The shadow engine now models MikroTik EoIP as a GRE payload-shape variant reached only from the outer IPv4 `protocol=47` selector path; outer IPv6 `next_header=47` still remains ordinary GRE.
- Shadow EoIP preserves the fixture-defined production classification rules exactly, including the strict `version=1 + key bit set + checksum clear + sequence clear + protocol type 0x6400` distinction from ordinary GRE, the normalized Tunnel ID -> `GRE(key=...)` path contribution, bounded inner-Ethernet continuation, and the current no-recursive-nested-EoIP rule.
- Unsupported GRE versions, routing-present variants, and malformed optional-field bounds must stop conservatively without contributing a physical path layer.

## MPLS Nuance

- Direct MPLS entry should remain registry-driven:
  - Ethernet / VLAN / QinQ `EtherType 0x8847`;
  - GRE protocol type `0x8847`.
- Shadow MPLS traversal should parse exactly one label shim per engine step rather than looping over a whole label stack inside one dissector.
- Bottom-of-stack payload inference in this stage is explicitly ordered:
  - IPv4 by first nibble `4`;
  - IPv6 by first nibble `6`;
  - then MPLS Ethernet pseudowire control-word / no-control-word continuation.
- MPLS pseudowire / control-word traversal is now shadow-supported through an explicit post-BoS selector plus a restricted inner Ethernet profile.
- The production MPLS pseudowire fixture contract in `tests/data/parsing/mpls_pw/README.md` now records the exact post-BoS production decision order:
  - direct IPv4 nibble `4`;
  - direct IPv6 nibble `6`;
  - accepted 4-byte pseudowire control word only when the first 16 bits are `0x0000`;
  - then plain inner Ethernet continuation.
- The shadow engine follows that same order:
  - direct IPv4 / IPv6 recognition has priority over Ethernet-pseudowire heuristics;
  - zero flags select the exact four-byte control word;
  - no control-word length field is interpreted;
  - control-word sequence is metadata only and does not affect persistent identity;
  - both control-word and no-control-word forms contribute the same conditional `MPLS PW` physical-path layer.
- Successfully parsed MPLS labels contribute `LayerKey::mpls(label)` in order; TTL and traffic-class bits remain non-identity metadata.

This is exactly the kind of branching that is too brittle in a centralized traversal and benefits from protocol-local modules with explicit selector transitions.

## AH And ESP Nuance

AH and ESP should follow the same registry-driven split while preserving current production selector domains.

- AH is an intermediate IP-security layer:
  - one shared bounded AH parser;
  - one IPv4 wrapper registered under `SelectorDomain::ip_protocol`;
  - one IPv6 wrapper registered under `SelectorDomain::ipv6_next_header`;
  - successful AH steps contribute `LayerKey::ah(spi)` and continue with the parsed Next Header only when a bounded child slice is valid.
- ESP is an opaque terminal IP-security layer:
  - one bounded ESP base-header parser reused for both IPv4 and IPv6 selector domains;
  - successful ESP steps contribute `LayerKey::esp(spi)`;
  - traversal stops at ESP without attempting payload decryption or inner continuation in this stage.

This shadow-only stage should cover direct IPv4 / IPv6 AH and ESP, IPv6-extension to AH handoff, nested AH continuation to already supported direct transports or plain-IP tunnel payloads, and conservative no-flow handling for malformed, truncated, and fragment-needs-reassembly cases. Production `PacketDecoder` semantics remain unchanged until the later import cutover stage.

## Generic Data Layer

The engine should support a conservative opaque-payload terminal event.

This is not the same as application protocol support.

Use cases:

- unsupported GRE or tunnel payload type;
- unresolved Ethernet continuation behind bounded inner payload;
- unknown PPP or SNAP payload that still deserves diagnostics.

Control-message bodies such as ICMP error quotes remain opaque at this stage. The first engine cutover does not traverse quoted inner packets carried inside ICMP or ICMPv6 payloads.

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

### Stage 1: RFC and types (`completed`)

- land this RFC and foundational value types;
- define shared engine/event/selector types;
- keep legacy `PacketDecoder` as production path.

### Stage 2: common direct modules in shadow tests (`completed`)

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

Within this stage, LLC/SNAP parity specifically means:
- IEEE 802.3 root and post-VLAN `< 0x0600` fields create bounded child slices instead of reusing the whole remaining frame;
- captured Ethernet padding or trailer bytes remain outside those child slices;
- supported SNAP PID continuation is registry-driven for IPv4, IPv6, and ARP;
- OUI is retained diagnostically but does not become part of persistent path identity.

### Stage 3: remaining currently supported modules in shadow tests (`completed`)

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

GRE, EoIP, MPLS, MPLS pseudowire, PPPoE / PPP, MACsec, and AH / ESP are now
implemented in the current shadow test suite; the remaining stage text records
the migration scope rather than a still-deferred status for those families.

For MACsec specifically, shadow dissection now implements the committed
production fixture contract under `tests/data/parsing/macsec/` plus
`tests/unit/MacsecPcapFixtureTests.cpp`. That contract remains intentionally
narrow: native Ethernet entry only through direct Ethernet II, outer single
VLAN `0x8100`, outer QinQ `0x88a8` + `0x8100`, or outer legacy-`0x9100`
stacking; fixed six-byte base SecTAG; optional eight-byte SCI; fixed assumed
trailing 16-byte ICV; no ICV validation; Short Length retained as metadata
only; optional Plain EtherType retained as metadata only for complete
`E=0` / `C=0` protected data with at least two visible bytes; and no protected
payload continuation into inner protocols. The shadow MACsec step emits facts
for diagnostics but contributes no persisted `ProtocolPath` layer and still
finalizes as `unrecognized` for production parity. Native Ethernet reachability
is isolated from unsupported embedded Ethernet selector contexts such as PBB
inner Ethernet, GRE TEB inner Ethernet, and Linux cooked roots. Production
import remains on legacy `PacketDecoder` until the broader cutover stage.

For PBB specifically, the current migration contract is defined by the committed
fixtures under `tests/data/parsing/pbb/` plus
`tests/unit/PbbPcapFixtureTests.cpp`. That contract now covers exact `0x88e7`
entry semantics, fixed 4-byte I-TAG parsing, I-SID-only identity behavior,
outer VLAN/QinQ/legacy-TPID entry before PBB, inner Ethernet continuation into
the currently supported IPv4/IPv6/ARP and inner VLAN/QinQ/LLC-SNAP subset,
known-but-unsupported nested continuations, complete-I-TAG/no-inner-Ethernet
cases, extra-tail payload-bounds behavior, and conservative
malformed/truncation behavior. The shadow engine now implements this subset
with a dedicated `PBB` step plus restricted `pbb_inner_frame` and
`pbb_inner_ether_type` selector domains so inner continuation remains narrower
than the global root-Ethernet path. In particular, inner IPv4/IPv6/ARP,
inner VLAN/QinQ/legacy-VLAN leading to the same restricted subset, and inner
IEEE 802.3 -> LLC/SNAP -> IPv4/IPv6/ARP are supported; inner PPPoE, nested
PBB, inner MPLS, and inner MACsec remain conservative no-flow stops.

For AH specifically, the shadow registry should keep the IPv4-versus-IPv6 next-selector distinction explicit instead of hiding it behind one domain-agnostic continuation. For ESP, the shadow registry should model the current production subset as an opaque terminal flow candidate keyed by SPI, without decrypting or decoding encrypted payload contents.

Stage 3 is no longer a pending scope marker for overlay families such as VXLAN,
Geneve, or GTP-U. Those families are implemented in shadow mode already; the
remaining work is parity closure and production integration.

### Stage 4: full semantic differential parity (`in progress`)

- compare the new engine against legacy behavior across all committed fixture families;
- verify tuple recognition, payload bounds, path contributions, stop reasons, and conservative no-flow behavior.

The July 22, 2026 static audit in
`docs/dissection-engine-parity-audit.md` shows two blocking semantic gaps
remaining before this stage can be considered complete:

- ARP import classification and persistent-path parity;
- PPPoE fixture `20_pppoe_bad_length_extra_payload.pcap` declared-boundary policy.

### Stage 5: single production import cutover (`not started`)

- make the engine the implementation behind the existing `PacketDecoder` / public decode API;
- continue to produce the existing `DecodedPacket` / `IngestedPacket` structures;
- do not introduce a production parser feature flag;
- do not expose a mixed legacy/new production decoder between intermediate commits.

### Stage 6: remove legacy centralized traversal (`not started`)

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

The branch is past foundational shadow implementation. The next work should be
sequenced as an explicit cutover-preparation plan:

1. resolve ARP import classification and path parity;
2. make an explicit PPPoE fixture-20 declared-boundary policy decision and align behavior to it;
3. implement an import adapter from `ImportDissectionFacts` into the existing `DecodedPacket` / `IngestedPacket` import contract;
4. add a full-session legacy-vs-shadow import parity harness covering summary counts, flow rows, connections, unrecognized rows, protocol-path registry contents, and persisted packet metadata;
5. run representative real-capture correctness and import-performance validation;
6. cut over production import in one dedicated change.

Keep production `PacketDecoder` unchanged until the remaining semantic blockers and
the import-integration prerequisites are all closed explicitly.
