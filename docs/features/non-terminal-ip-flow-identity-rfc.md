# Non-Terminal IP Flow Identity RFC

Status: Pre-implementation RFC.

This document specifies the intended next-generation Pcap Flow Lab Flow
grouping model for non-terminal IP endpoint identity. It is not implemented in
the current production code.

Current implemented behavior remains documented in
[`docs/protocols/protocol_path_flow_identity.md`](../protocols/protocol_path_flow_identity.md).
This RFC defines the future target contract so implementation, tests,
indexing, and documentation do not drift.

## Purpose

Current recognized-flow identity is conceptually:

```text
terminal tuple
+ normalized ProtocolPathId
```

In this RFC, `terminal tuple` means the effective/terminal:

- source IP;
- destination IP;
- source port;
- destination port;
- `ProtocolId`.

That model correctly distinguishes structural and namespace-bearing protocol
paths such as VLAN VID, MPLS label, VXLAN VNI, Geneve VNI, GTP-U TEID, GRE key,
AH SPI, and ESP SPI. It intentionally keeps concrete IP addresses and transport
ports out of `ProtocolPath`.

The remaining gap is that packets can have the same terminal tuple and the
same normalized `ProtocolPathId`, but different concrete non-terminal IP
endpoint paths. In the current model those packets may merge into one
user-visible Flow. The future default behavior MUST distinguish those
observed carrier/tunnel IP endpoint paths.

Example packet set A:

```text
EthernetII
-> IPv4 111.111.111.111 -> 222.222.222.222
-> UDP
-> GTP-U TEID 0x01020304
-> IPv4 10.10.10.1 -> 10.10.10.2
-> TCP 50123 -> 443
```

Example packet set B:

```text
EthernetII
-> IPv4 123.123.123.123 -> 234.234.234.234
-> UDP
-> GTP-U TEID 0x01020304
-> IPv4 10.10.10.1 -> 10.10.10.2
-> TCP 50123 -> 443
```

Under the future default, A and B are different Flows because the concrete
non-terminal IP endpoint context differs. Users who want logical inner-flow
grouping independent of carrier IP endpoints MUST be able to opt into that
relaxed behavior through an import setting.

## Current Architecture

Current user-visible Flow remains one bidirectional communication.

Current implementation facts:

- `ConnectionV4` / `ConnectionV6` is the bidirectional technical entity.
- `flow_a` is the first-observed direction.
- `flow_b` is the reverse/opposite direction.
- UI Endpoint A/B follows first-observed `flow_a`.
- `ConnectionKey.first` / `ConnectionKey.second` is canonical sorted identity
  and is not UI Endpoint A/B.
- `FlowKeyV4` / `FlowKeyV6` currently contains terminal directional source and
  destination IP, terminal source and destination port, `ProtocolId`, and
  `ProtocolPathId`.
- `ConnectionKeyV4` / `ConnectionKeyV6` currently contains canonical terminal
  endpoints plus `ProtocolId` and `ProtocolPathId`.
- Current stable index revision is `19`.

Current import settings already support identity normalization:

- `Ignore VLAN and MPLS layers when grouping flows`
- `Ignore GTP-U TEIDs when grouping inner flows`

The new design follows that philosophy: strict identity by default, with an
explicit import-time relaxation setting.

## Future Grouping Contract

Future default recognized-flow identity is conceptually:

```text
terminal tuple
+ normalized ProtocolPathId
+ NonTerminalIpContextId
```

The conceptual ID type is:

```cpp
using NonTerminalIpContextId = std::uint32_t;
```

The exact production declaration may be adjusted during implementation, but the
semantic contract is a compact capture-local integer ID.

`NonTerminalIpContextId = 0` is reserved as the empty/default identity. It means
there are no identity-significant non-terminal IP endpoint levels for this
packet/grouping operation. Ordinary traffic such as:

```text
EthernetII -> IPv4 -> TCP
```

has no non-terminal network level and SHOULD use ID `0` without owning or
interning a context object.

ID `0` MUST be reserved only for the empty or ignored grouping context. It MUST
NOT identify a non-empty interned context.

## Non-Terminal IP Levels

A network-layer occurrence is non-terminal when another deeper IP/network
endpoint level becomes the effective terminal layer used for the terminal Flow
tuple.

Direct traffic:

```text
IPv4 -> TCP
```

Non-terminal levels: none.

Terminal: `IPv4/TCP`.

GTP-U traffic:

```text
IPv4
-> UDP
-> GTP-U
-> IPv4
-> TCP
```

Non-terminal levels:

- level 1: outer IPv4

Terminal: inner `IPv4/TCP`.

GRE plus GTP-U nesting:

```text
IPv4
-> GRE
-> IPv4
-> UDP
-> GTP-U
-> IPv6
-> TCP
```

Non-terminal levels:

- level 1: outer IPv4
- level 2: middle IPv4

Terminal: `IPv6/TCP`.

The design MUST support zero, one, two, or more non-terminal network levels
within the existing bounded dissection model. It MUST NOT be designed around
exactly one outer IP layer.

## NonTerminalIpContext

Conceptually:

```text
NonTerminalIpContext
    ordered non-terminal network endpoint levels
```

Each level contains at minimum:

- network/address family needed to interpret the addresses;
- directional source IP;
- directional destination IP.

Example:

```text
Level 1:
    IPv4
    111.111.111.111 -> 222.222.222.222

Level 2:
    IPv4
    123.123.123.123 -> 234.234.234.234
```

Terminal IP addresses MUST NOT be duplicated in `NonTerminalIpContext`; they
remain represented by the terminal tuple. The context MUST NOT include terminal
ports, non-terminal transport ports, or `ProtocolPathId`.

`ProtocolPathId` and `NonTerminalIpContextId` are separate components of Flow
identity.

Two non-empty `NonTerminalIpContext` values are equal only when:

- they have the same number of ordered non-terminal network levels;
- each corresponding level has the same address family;
- each corresponding level has the same canonical source IP address;
- each corresponding level has the same canonical destination IP address.

Different level counts MUST NOT compare equal. Level ordering is
identity-significant.

## ProtocolPath Remains Structural

This RFC does not redefine `ProtocolPath` to contain concrete IP addresses.

The structural identity remains conceptually:

```text
EthernetII
-> IPv4
-> UDP
-> GTP-U(teid=0x01020304)
-> IPv4
-> TCP
```

It does not become:

```text
EthernetII
-> IPv4(111.111.111.111 -> 222.222.222.222)
-> UDP
-> GTP-U(teid=0x01020304)
-> IPv4(10.10.10.1 -> 10.10.10.2)
-> TCP
```

Concrete non-terminal IP endpoints belong to `NonTerminalIpContext`.

Rationale:

- `ProtocolPath` remains structural/namespace identity.
- It remains useful for Protocol Path statistics and filtering.
- Adding concrete endpoint values directly would dramatically increase
  `ProtocolPathRegistry` cardinality.
- Endpoint identity and structural path identity are separate concerns.
- `ProtocolPathId` and `NonTerminalIpContextId` compose naturally in Flow
  identity.

Future user-facing presentation MAY combine structural path and concrete
endpoint information, but that MUST NOT change internal `ProtocolPath`
semantics.

## Non-Terminal Transport Ports

Non-terminal UDP/TCP/SCTP ports MUST NOT participate in generic bidirectional
Flow grouping.

This is intentional scope reduction, not an accidental omission. Some supported
tunnel protocols use directional, service, or entropy port behavior that is not
a symmetric reversible transport tuple. Important current examples include
VXLAN, Geneve, and GTP-U.

Therefore:

- non-terminal transport ports are not part of `NonTerminalIpContext`;
- they do not get a grouping ID;
- no retained Flow-level outer-port metadata is required by this RFC;
- Advanced Flow Filter outer-port support is out of scope;
- packet-level dissection may still show real outer transport headers normally.

## Import Setting

Add a new import/grouping setting conceptually named:

```text
Ignore non-terminal IP endpoints when grouping flows
```

Default: `false` / `No`.

Default behavior: non-terminal IP endpoints participate in grouping identity.

When enabled, non-terminal IP endpoints are ignored for grouping. Conceptually
grouping behaves as if:

```text
NonTerminalIpContextId = 0
```

even when packets contain non-terminal IP levels.

The setting is analogous to the existing settings:

- `Ignore VLAN and MPLS layers when grouping flows`
- `Ignore GTP-U TEIDs when grouping inner flows`

Based on current stable-key naming, the likely internal stable setting key is:

```text
ignore_non_terminal_ip_endpoints_when_grouping_flows
```

Implementation should verify final naming against the settings DTO, frontend
bridge, CLI JSON, and index provenance code before changing production.

Because outer-IP filtering is not part of this RFC, the relaxed setting does
not require retaining ignored non-terminal endpoint contexts for later Flow
filtering. Relaxed mode SHOULD remain cheap.

## Canonicalization

Bidirectional identity canonicalization is critical.

Given forward:

```text
outer A -> B
middle C -> D
terminal X -> Y
```

and reverse:

```text
outer B -> A
middle D -> C
terminal Y -> X
```

both packets MUST resolve to the same bidirectional `Connection` identity.

The entire non-terminal endpoint chain MUST be canonicalized coherently with
terminal `ConnectionKey` orientation. Implementations MUST NOT independently
sort every non-terminal IP pair, because per-level independent sorting can
destroy side correlation across levels.

Implementations SHOULD reuse the endpoint ordering/canonicalization semantics
used by the current `ConnectionKey` / `make_connection_key` path instead of
inventing a separate terminal endpoint comparator.

Conceptual rule:

```text
if packet terminal orientation matches canonical connection orientation:
    keep src/dst orientation at every non-terminal level
else:
    swap src/dst at every non-terminal level
```

The ordered level sequence remains outer to inner.

For the normal case where the two terminal endpoints differ, terminal
`ConnectionKey` canonical orientation determines whether all non-terminal
source/destination pairs are kept or swapped.

For the rare case where the terminal endpoints are exactly equal and terminal
orientation cannot distinguish forward from reverse, the implementation MUST
still choose a deterministic canonical representation for a non-empty context.
Conceptually compare:

```text
observed whole ordered context
```

against:

```text
the same whole ordered context with source/destination swapped at every level
```

and choose one deterministic representation, for example the lexicographically
lesser representation under the context's canonical comparison. The comparison
MUST operate on the complete ordered chain and MUST NOT independently sort
individual levels.

This is distinct from:

- canonical identity orientation used by `ConnectionKey`;
- first-observed `flow_a` / `flow_b`;
- user-facing Endpoint A / Endpoint B.

Those concepts MUST NOT be conflated.

## Asymmetric Carrier Paths

Default strict grouping preserves observed carrier IP identity.

Example forward:

```text
outer A -> B
terminal X -> Y
```

Example reverse:

```text
outer C -> A
terminal Y -> X
```

If canonical non-terminal contexts differ, the packets belong to different
user-visible Flows under the default policy. This is not a false split under
the new default.

Users who prefer logical inner communication independent of carrier IP
endpoints can enable `Ignore non-terminal IP endpoints when grouping flows`.

## Context Registry

Introduce a capture-level context registry, conceptually:

```text
NonTerminalIpContextRegistry
```

It maps:

```text
NonTerminalIpContextId -> immutable NonTerminalIpContext
```

and interns equivalent canonical contexts.

Goals:

- avoid embedding variable-length endpoint arrays directly in `FlowKey`,
  `ConnectionKey`, `Flow`, or `Connection`;
- reuse common tunnel/carrier contexts across many terminal Flows;
- keep ordinary non-encapsulated traffic on the ID-0 fast path;
- support nested multiple-level contexts;
- keep context storage capture-scoped.

Real operator traffic has shown repeated carrier endpoint contexts across many
terminal Flows, so context reuse is a realistic expected workload. This RFC
does not include private capture names, paths, IP addresses, or proprietary
traffic details.

## Import Hot-Path Requirements

This feature affects raw capture open. It MUST preserve fast time-to-usable
Flow List for very large captures as a core product requirement.

Implementation requirements:

- no second packet dissection pass;
- no additional source-file read for context construction;
- no per-packet dynamic allocation solely to collect candidate non-terminal
  levels;
- no variable `std::vector` construction on the common packet path before it is
  known to be necessary;
- use bounded/fixed temporary collection integrated with current dissection
  traversal;
- ordinary non-nested traffic follows a very cheap ID-0 fast path;
- context lookup/interning is required only when the packet has a non-empty
  non-terminal IP context and non-terminal IP endpoints are identity-significant
  under the active import/grouping settings;
- when `Ignore non-terminal IP endpoints when grouping flows` is enabled, the
  implementation SHOULD use context ID `0` directly and avoid context
  interning because this RFC does not require retaining ignored contexts for
  later filtering;
- no extra full terminal-tuple hash lookup beyond what the final architecture
  requires;
- measure capture-open performance before and after implementation.

Performance measurements SHOULD use the methodology documented in
[`docs/benchmarks/capture-open-performance.md`](../benchmarks/capture-open-performance.md),
including comparison against benchmark ID `CAPOPEN-2026-10-03-01` where useful.

## Transient Identity Versus Retained Directional State

Current `FlowKey` serves two roles:

1. packet/import directional identity;
2. retained directional state inside `Connection.flow_a` / `Connection.flow_b`.

Future architecture SHOULD separate those roles.

### Full Transient Flow Identity Key

A full directional identity object, likely still named `FlowKeyV4` /
`FlowKeyV6`, carries:

- terminal directional source/destination IP;
- terminal directional source/destination port;
- `ProtocolId`;
- `ProtocolPathId`;
- `NonTerminalIpContextId`.

It is used by:

- import/grouping;
- `ConnectionKey` construction;
- `FlowHintService`;
- other stateful FlowKey-keyed import-time behavior.

### Retained Directional Flow State

Inside `Connection.flow_a` / `Connection.flow_b`, retain only directional
terminal endpoint data required after `Connection` lookup:

- source/destination terminal IP;
- source/destination terminal port.

Use a compact type conceptually similar to:

```text
DirectionalEndpointKeyV4
DirectionalEndpointKeyV6
```

Final naming may be decided during implementation.

Shared identity fields remain authoritative in the parent `Connection`:

- `ProtocolId`;
- `ProtocolPathId`;
- `NonTerminalIpContextId`.

## FlowHintService Isolation

Current `FlowHintService` has stateful `FlowKey`-keyed maps for at least:

- QUIC Initial processing;
- retained/split TLS ClientHello processing.

Future packets with the same terminal tuple and same `ProtocolPathId` but
different `NonTerminalIpContextId` must not share this state, because they are
different future user-visible Flows/Connections.

Therefore:

```text
context ID in full transient FlowKey: yes
context ID in ConnectionKey: yes
context ID in retained directional endpoint state: no
```

## ConnectionKey Contract

Future `ConnectionKeyV4` / `ConnectionKeyV6` SHOULD contain:

- canonical terminal endpoints;
- `ProtocolId`;
- `ProtocolPathId`;
- `NonTerminalIpContextId`.

This is the authoritative bidirectional grouping identity used by
`ConnectionTable`.

After the `Connection` has been found, protocol, path, and context are already
known from the parent connection identity. `Connection::add_packet` should
eventually route packets to `flow_a` / `flow_b` using retained directional
terminal endpoints rather than complete `FlowKey` equality.

This is a runtime-model consequence of moving shared identity to the parent
`Connection`, not only a performance optimization.

## Measured Current Layout Facts

The following measurements come from the current Windows MinGW/GCC development
build environment used for local layout probing.

Measured current types:

```text
FlowV4 = 64 bytes
FlowV6 = 88 bytes

ConnectionV4 = 312 bytes
ConnectionV6 = 384 bytes

PacketRef = 40 bytes

unordered_map<ConnectionKeyV4, ConnectionV4>::value_type = 336 bytes
unordered_map<ConnectionKeyV6, ConnectionV6>::value_type = 432 bytes
```

`unordered_map::value_type` size does not include allocator/node overhead.

Measured compact retained-flow surrogates:

```text
FlowV4: 64 -> 56 bytes
FlowV6: 88 -> 80 bytes
```

Therefore:

```text
ConnectionV4: 312 -> approximately 296 bytes
ConnectionV6: 384 -> approximately 368 bytes
```

Expected direct retained structure saving:

```text
16 bytes per Connection
16 MB per 1,000,000 Connections
19.2 MB per 1,200,000 Connections
```

These are direct structure calculations using decimal MB arithmetic. They MUST
NOT be presented as exact total RSS savings.

## Measured Future ID Layout Cost

The local layout probe showed that adding one `std::uint32_t` context ID to
full keys increases:

```text
FlowKeyV4: 20 -> 24 bytes
FlowKeyV6: 44 -> 48 bytes

ConnectionKeyV4: 24 -> 28 bytes
ConnectionKeyV6: 44 -> 48 bytes
```

Simple field reordering did not eliminate this growth. There is no free padding
in the current keys sufficient to absorb the context ID.

This is one reason the context ID MUST NOT also be duplicated into retained
`flow_a` and `flow_b` directional state. Exact full-container/RSS impact must
be measured in a real implementation.

## Deferred Connection.key Duplication

Current `unordered_map<ConnectionKey, Connection>` stores:

- one `ConnectionKey` as the map key;
- another copy as `Connection.key`.

This retained duplication is known. This RFC does not solve it.

Reasons:

- many consumers receive stable `Connection*`;
- `Connection` currently remains self-describing;
- removing `Connection.key` changes ownership/access patterns significantly;
- this is a separate architecture and performance decision.

## Index Revision Implications

This feature changes grouping identity and persistent metadata. It should be
implemented as a new incompatible stable index revision. Current production is
revision `19`; revision `20` is the expected next revision if no other
incompatible index feature lands first.

Conceptual future index shape:

```text
Connection shared identity
    canonical terminal endpoints
    ProtocolId
    ProtocolPathId
    NonTerminalIpContextId

flow_a
    directional terminal endpoints
    existing directional counters/state

flow_b
    directional terminal endpoints
    existing directional counters/state

capture-level NonTerminalIpContext registry
    context ID -> ordered network endpoint levels
```

Do not continue serializing shared `protocol`, `ProtocolPathId`, or context ID
inside each directional Flow merely to mimic revision 19.

First-observed orientation remains reconstructable from `flow_a` directional
endpoints. Exact binary serialization layout is open until implementation.
Index compatibility rules remain consistent with current project behavior:
older incompatible stable revisions are rejected with rebuild-required
diagnostics rather than silently reinterpreted.

## Grouping Setting Interactions

The final grouping identity is formed after all enabled normalization rules.

Terminal tuple:

- always identity-significant.

ProtocolPath:

- normalized by settings such as `Ignore VLAN and MPLS layers when grouping
  flows`.

GTP-U TEID:

- normalized by `Ignore GTP-U TEIDs when grouping inner flows`.

Non-terminal IP endpoint context:

- normalized by `Ignore non-terminal IP endpoints when grouping flows`.

These settings are independent dimensions:

- ignoring VLAN/MPLS MUST NOT automatically ignore outer IP endpoints;
- ignoring TEID MUST NOT automatically ignore outer IP endpoints;
- ignoring outer IP endpoints MUST NOT remove TEID from `ProtocolPath`.

## Protocol-Family Applicability

The model is generic to supported nested IP traversal, not GTP-U-specific.

Expected applicability includes supported paths such as:

- GTP-U;
- VXLAN;
- Geneve;
- GRE;
- EoIP;
- IP-in-IP;
- AH continuation where deeper IP is exposed;
- nested combinations of these.

VLAN, MPLS, PBB, PPP, PPPoE, and similar non-IP structural layers do not by
themselves create `NonTerminalIpContext` network endpoint levels.

ESP cases MUST remain conservative according to what the current parser can
actually expose. The implementation must not invent inner endpoint visibility
for encrypted or opaque payloads.

## Correctness Fixture Requirements

Before implementation is complete, synthetic tests MUST cover at least the
following cases.

Basic split:

- same terminal tuple;
- same `ProtocolPath`;
- different outer IP pair;
- expected default result: two Flows.

Relaxed merge:

- same fixture with `Ignore non-terminal IP endpoints when grouping flows =
  true`;
- expected result: one Flow where other identity dimensions are equal.

Reverse direction:

```text
forward: outer A -> B, terminal X -> Y
reverse: outer B -> A, terminal Y -> X
```

All other normalized grouping dimensions, especially normalized
`ProtocolPathId`, must be equal. The test MUST NOT let different GTP-U TEIDs,
VLAN/MPLS identity, VNI, GRE key, SPI, or other `ProtocolPath` identity
determine the result.

Expected result: one `Connection` with `flow_a` plus `flow_b`.

Different reverse carrier:

```text
forward: outer A -> B, terminal X -> Y
reverse: outer C -> A, terminal Y -> X
```

All other normalized grouping dimensions, especially normalized
`ProtocolPathId`, must be equal. The intended differing dimension is only the
`NonTerminalIpContext`.

Expected default result: different Flows/Connections.

Nested two-level context:

- at least two non-terminal IP levels participate;
- level order is preserved.

Context-order distinction:

- the same set of addresses in different ordered level relationships must not
  collide.

IPv6 coverage:

- IPv6 outer;
- IPv4 outer / IPv6 terminal;
- IPv6 outer / IPv4 terminal.

FlowHintService isolation:

- same terminal tuple/path but different context IDs must not share QUIC
  Initial state;
- same terminal tuple/path but different context IDs must not share pending TLS
  ClientHello continuation state.

Existing hint test seams should be reused where practical.

## Current Fixtures That Will Change

Current repository fixtures intentionally document v1 behavior where outer
carrier variation can merge. They are not broken tests; they must be
deliberately migrated when the new default identity semantics are implemented.

Known current fixtures/tests include:

- `tests/data/parsing/vxlan/22_vxlan_identity_outer_carrier_variation_same_flow.pcap`
  with `tests/unit/VxlanPcapFixtureTests.cpp` and
  `tests/unit/CommonDirectVxlanDissectionTests.cpp`.
- `tests/data/parsing/geneve/21_geneve_identity_outer_carrier_variation_same_flow.pcap`
  with `tests/unit/GenevePcapFixtureTests.cpp` and
  `tests/unit/CommonDirectGeneveDissectionTests.cpp`.
- `tests/data/parsing/ip_encapsulation/13_same_inner_tuple_different_outer_ipv4_tunnels.pcap`
  with `tests/unit/IpEncapsulationPcapFixtureTests.cpp` and the parsing
  fixture documentation.
- `tests/data/parsing/eoip/26_same_tunnel_same_inner_tuple_different_outer_ipv4_endpoints.pcap`
  with `tests/unit/EoipPcapFixtureTests.cpp` and
  `tests/unit/CommonDirectEoipDissectionTests.cpp`.

When the new default is implemented, preserve coverage for the old merge
behavior under the new ignore-non-terminal-IP setting where it remains a valid
user-visible option.

## Real-World Validation Plan

A private/local operator capture may be used for internal validation only. Do
not commit its filename, filesystem path, IP addresses, or proprietary
identifying data.

Validation should measure:

- total Flows before/after strict context grouping;
- number of Flows with zero non-terminal levels;
- number of Flows with one non-terminal level;
- number of Flows with two or more levels;
- total unique `NonTerminalIpContext` values;
- context reuse distribution;
- average/median/max Flows per context where useful;
- context counts per `ProtocolPath` where useful;
- raw capture open time;
- resident memory;
- index size/open time after persistence is implemented.

If the capture has direction-dependent VLAN behavior, bidirectional tests may
require relaxed VLAN/MPLS grouping or dedicated synthetic fixtures.

Private capture observations are validation evidence, not public product
contract.

## Performance Acceptance Criteria

Implementation acceptance criteria:

1. Direct non-tunneled traffic uses context ID `0` with no owned context object.
2. No per-packet heap allocation is allowed solely for temporary context
   construction.
3. No second full dissection or source read is allowed.
4. Context collection integrates into current bounded dissection traversal.
5. Context interning occurs only when a non-empty context is identity-significant
   under active import/grouping settings.
6. Capture-open performance is measured against the current documented
   benchmark methodology.
7. A ProtocolPath/tunnel-heavy capture is included in focused regression
   measurements.
8. Any measurable regression is understood before merge.
9. Memory changes are measured, not inferred only from struct sizes.

This RFC does not prescribe an arbitrary percentage threshold.

## Implementation Staging

### Stage 1 - Domain Representation And Canonicalization

- bounded temporary non-terminal IP collection;
- canonical context representation;
- context registry;
- `NonTerminalIpContextId`;
- unit tests for equality/canonicalization.

### Stage 2 - Import/Grouping Integration

- full transient `FlowKey` carries context ID;
- `ConnectionKey` carries context ID;
- `ConnectionTable` grouping uses the expanded key;
- compact retained directional endpoint state;
- `FlowHintService` isolation;
- synthetic fixtures.

### Stage 3 - Import Setting

- `Ignore non-terminal IP endpoints when grouping flows`;
- provenance;
- CLI/UI settings integration;
- tests.

### Stage 4 - Index Persistence

- next stable index revision;
- context registry persistence;
- compact directional flow persistence;
- raw/index parity tests.

### Stage 5 - Statistics/Presentation Adjustments

Only implement presentation changes required for correct current Flow and
ProtocolPath semantics. Do not add non-terminal IP Advanced Flow Filter support
in this stage unless separately approved.

### Stage 6 - Performance And Real-World Validation

- layout/RSS measurements;
- capture-open benchmark regression;
- operator-capture cardinality/reuse measurements;
- tunnel-heavy focused benchmark.

## Non-Goals

This RFC explicitly defers:

- outer/non-terminal transport ports in Flow identity;
- Flow-level retained outer-port observations;
- Advanced Flow Filter by non-terminal IP address;
- Advanced Flow Filter by non-terminal port;
- adding concrete IP addresses to `ProtocolPath`;
- redesigning existing GTP-U TEID semantics;
- redesigning VLAN/MPLS identity semantics;
- redesigning `ConnectionTable` ownership;
- removing duplicate `Connection.key`;
- full generic physical packet-path persistence;
- storing per-packet context IDs in `PacketRef`;
- transport/session reconstruction changes;
- protocol-specific dynamic grouping policies;
- redesigning user-visible Flow terminology.

Future work may revisit some of these separately.

## Open Implementation Questions

Frozen product decisions in this RFC:

- outer/non-terminal IP endpoints participate by default;
- the ignore setting exists;
- non-terminal transport ports do not participate;
- `ProtocolPath` remains separate and structural;
- the context is capture-scoped and interned behind a compact ID;
- context ID belongs in full transient `FlowKey` and `ConnectionKey`;
- context ID does not belong in retained directional Flow state.

Open implementation details:

- exact context registry storage/container;
- exact fixed-size temporary builder representation;
- optimal context hash implementation;
- exact type/member names;
- exact index binary layout;
- whether context canonicalization happens before or during interning;
- whether a specialized fast path avoids constructing a full context view for
  common one-level tunnels;
- exact placement/order of new `std::uint32_t` fields after prototype layout
  measurements.

## Decision Summary

- User-visible Flow remains bidirectional.
- Default grouping becomes terminal tuple plus normalized `ProtocolPathId` plus
  canonical ordered non-terminal IP context.
- Concrete non-terminal IP endpoints are identity-significant by default.
- A new import setting can ignore them for grouping.
- Non-terminal transport ports do not participate.
- `ProtocolPath` remains structural/namespace identity and does not gain
  concrete IP addresses.
- `NonTerminalIpContext` is capture-scoped and interned behind a compact
  `std::uint32_t` ID.
- ID `0` represents no grouping-relevant non-terminal IP context.
- Full transient `FlowKey` carries the context ID.
- `ConnectionKey` carries the context ID.
- Retained `flow_a` / `flow_b` store compact directional terminal endpoint
  state only.
- Parent `Connection` owns shared protocol/path/context identity.
- `FlowHintService` state must be isolated by the new full identity.
- The next index revision persists shared connection identity and the context
  registry without repeating shared identity inside directional flow records.
- Large-capture open performance remains a hard design constraint.
- Outer-port filtering and general carrier-observation storage are out of
  scope.
