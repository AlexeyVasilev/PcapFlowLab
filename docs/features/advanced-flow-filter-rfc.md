# Advanced Flow Filter RFC

Status: staged RFC with initial backend compile/evaluate foundation.

This document defines the product and backend-filter model for the Advanced
Flow Filter in Pcap Flow Lab.

The current backend stage introduces a separate structured filtering subsystem
without changing legacy text-filter behavior, CLI syntax, UI, or index
serialization.

Related RFCs:

- [Flow Aggregate Metadata RFC](flow-aggregate-metadata-rfc.md)
- [Index v15 Container RFC](index-v15-container-rfc.md)

## Goal

Advanced Flow Filter operates on canonical flows/connections and indexed
metadata.

Normal filter evaluation must not require rescanning the source capture or
re-running expensive packet dissection just to answer an ordinary flow query.

Unrecognized packets are not canonical flows and are outside the initial
Advanced Flow Filter scope.

## Current Backend Stage

The implemented backend stage is intentionally separate from the lightweight
legacy `FlowQuery` / `--filter` text-filter path.

The architecture is:

```text
AdvancedFlowFilterSpec
    -> compile
CompiledAdvancedFlowFilter
    -> evaluate
AdvancedFlowFilterResult
```

`AdvancedFlowFilterSpec` is declarative: it describes what the caller wants to
match.

`CompiledAdvancedFlowFilter` is execution-oriented: it stores precompiled
membership tables, normalized numeric predicates, precompiled service
predicates, and the fixed execution plan.

Future CLI usage is expected to remain conceptually distinct:

- `--filter "QUIC"` for the legacy text filter
- `--adv-filter <filter-file>` for the structured Advanced Flow Filter

Those modes are expected to be mutually exclusive. The current backend stage
does not add `--adv-filter`, does not parse saved filter files, and does not
integrate Advanced Flow Filter into `FlowQuery`.

## Current State

The current repository already provides the major identity and presentation
layers that a filter can build on:

- canonical IPv4/IPv6 flow/connection inventory
- canonical A/B endpoint orientation
- canonical transport/flow protocol identity
- detected protocol hints
- service hints
- Protocol Path identity and registry
- flow-level Statistics
- selected-flow Analysis
- persistent capture indexes

Verified current-state facts from the current local branch:

- Canonical connections already store total packet count and total original-byte
  volume at the connection level.
- Directional `flow_a` / `flow_b` state already stores packet counts and
  original-byte totals, so A->B / B->A packet and original-byte aggregates
  already exist in memory and in current index serialization through serialized
  `FlowV4` / `FlowV6`.
- Flow identity already includes `protocol_path_id` in `FlowKeyV4`,
  `FlowKeyV6`, `ConnectionKeyV4`, and `ConnectionKeyV6`.
- Fragmentation state already exists as `has_fragmented_packets` and
  `fragmented_packet_count` on canonical connections and is currently serialized
  in the index.
- Detected protocol hint and service hint already exist on canonical
  connections and are currently serialized in the index.
- QUIC/TLS version hints already exist on canonical connections in memory, but
  they are not serialized in the current index format.
- Captured-byte totals, time bounds, TCP SYN/FIN/RST counts, and packet-size
  extrema now exist as compact per-connection aggregate metadata in
  `ConnectionAggregateStats`.

## Current Implemented Predicate Families

The initial backend stage supports these predicate families:

- Protocol Path
- flow protocol (`ProtocolId`)
- detected protocol (`FlowProtocolHint`, including current possible-TLS /
  possible-QUIC semantics from `AnalysisSettings`)
- ports
- cheap numeric / aggregate metadata
- directionality
- service string metadata

Different active families combine with AND.

Multiple include predicates inside one family combine with OR.

Exclusion predicates reject a flow when any exclusion matches.

An empty `AdvancedFlowFilterSpec` matches every listable flow.

Arbitrary nested Boolean expressions remain deferred.

In the current backend stage, directionality is intentionally limited to the
two states that fit the listable-flow model:

- `unidirectional`: `flow_a` has packets and `flow_b` has none
- `bidirectional`: both `flow_a` and `flow_b` have packets

## Longer-Term Planned Filter Families

Beyond the current backend stage, the broader planned family set is:

### IP addresses and networks

- multiple IPv4/IPv6 addresses
- CIDR networks
- endpoint scope:
  - either endpoint
  - endpoint A
  - endpoint B
- future "between two networks" semantics

### Ports

- multiple exact ports
- port ranges
- endpoint scope:
  - either endpoint
  - endpoint A
  - endpoint B

### Flow identity and protocol

These concepts must remain distinct:

- IP family
- canonical/flow protocol:
  - TCP
  - UDP
  - SCTP
  - ICMP
  - ICMPv6
  - IGMP
  - ARP
- detected higher-level protocol:
  - TLS
  - QUIC
  - HTTP
  - DNS
  - mDNS
  - others already represented by `FlowProtocolHint`
- known / unknown detected protocol

### Service metadata

- multiple strings
- case-insensitive contains
- equals
- starts-with
- known / unknown service
- include / exclude support

Regex is deferred.

### Flow packet count

- minimum and/or maximum packet count

### Flow byte volume

- original bytes: minimum and/or maximum
- captured bytes: minimum and/or maximum

### Protocol Path

Support multiple path predicates.

Planned path-matching semantics:

- kind-only path/prefix
- identifier-aware prefix
- exact terminal path
- path contains a layer kind
- direct identifier matching where applicable

Examples of identifier-bearing layers already represented in current Protocol
Path identity include:

- VLAN VID
- MPLS label
- VXLAN VNI
- Geneve VNI
- GTP-U TEID
- GRE key
- AH SPI
- ESP SPI

Longer-term UI intent:

- a dedicated "Add Protocol Path..." selector should create the same backend
  predicate type used by the common filter model
- Statistics -> Show flows should eventually emit the same common Protocol Path
  predicate instead of maintaining a separate filtering mechanism

### Protocol-specific versions

- TLS 1.2
- TLS 1.3
- QUIC v1
- QUIC v2
- currently represented draft versions
- unavailable / unknown where meaningful

### Packet-size aggregates

Initial useful predicates:

- largest original packet length
- largest captured packet length

Minimum packet-size predicates are deferred.

### Packet/flow conditions

- fragmented packets present / absent
- fragmented packet count
- truncated packets present / absent
- truncated packet count
- TCP SYN packet count
- TCP FIN packet count
- TCP RST packet count

These remain factual predicates only. Semantic labels such as "failed
connection" are explicitly out of scope.

### Flow time

Planned semantics:

- started after / before
- ended after / before
- overlaps an interval
- fully inside an interval
- relative-to-capture-start time as a later secondary UI mode

### Duration

- minimum and/or maximum duration

### Directionality

Using canonical A/B orientation:

- A->B packet count
- B->A packet count
- A->B original bytes
- B->A original bytes
- current backend predicate values:
  - unidirectional
  - bidirectional
- derived packet dominance / ratio
- derived byte dominance / ratio

### Derived rate predicates

Where source aggregates are sufficient:

- average packets/sec
- average original-byte data rate

These should be derived in O(1) from stored aggregates and not persisted as
independent long-lived metadata.

## Fixed Execution Order

The declarative filter specification does not define hot-path execution order.

The current backend stage uses this fixed execution order:

1. initial candidate scope
2. Protocol Path membership
3. flow protocol / detected protocol
4. ports
5. cheap numeric / aggregate predicates and directionality
6. service predicates

Service matching is deliberately last.

Protocol Path predicates are resolved during compile to dense
`ProtocolPathId` membership tables derived from the session's
`ProtocolPathRegistry`.

The evaluator uses one candidate loop with early rejection. It does not:

- inspect `PacketRef` collections
- read source capture bytes
- build rendered `FlowRow` strings for rejected candidates
- dynamically reorder predicates

## Composition Rules For Initial Version

The initial composition model is:

- OR within one filter section/list
- AND between independent filter sections
- include / exclude predicates

Example:

```text
IP in {A,B,C}
AND
detected protocol in {TLS,QUIC}
AND
packets between 100 and 1200
```

Arbitrary nested Boolean expression trees such as:

```text
(A && B) || !(C && D)
```

are deferred.

## Metadata Foundation Required By This RFC

The filter can already rely on current canonical state for:

- endpoint identity
- transport protocol identity
- Protocol Path identity
- total packet count
- total original bytes
- directional packet counts
- directional original-byte totals
- fragmentation count
- detected protocol hint
- service hint

The following compact per-connection aggregates are provided by
[Flow Aggregate Metadata RFC](flow-aggregate-metadata-rfc.md) and are used by
the current Advanced Flow Filter backend stage:

- first timestamp
- last timestamp
- captured-byte total
- truncated-packet count
- max original packet length
- max captured packet length
- TCP SYN count
- TCP FIN count
- TCP RST count

The current backend stage evaluates numeric predicates from that aggregate
foundation rather than by rescanning `PacketRef` vectors.

## Derived Data

The following values should remain derived rather than persisted as separate
stored filter fields:

- duration
- packets/sec
- average original-byte data rate
- average original packet size
- unidirectional / bidirectional
- packet ratio / packet dominance
- byte ratio / byte dominance
- has fragmented packets
- has truncated packets
- known / unknown detected protocol
- known / unknown service

Rationale:

- these are direct O(1) derivations from a smaller authoritative aggregate set
- persisting both source aggregates and many redundant derived flags increases
  index size and migration burden
- speculative metadata should not be stored merely because it might be
  filterable later

## Deferred

Deferred from the initial implementation:

- IP/CIDR predicates
- TLS/QUIC version predicates
- rate predicates
- regex service matching
- arbitrary nested Boolean expression trees
- minimum original packet length
- minimum captured packet length
- largest packet gap
- TCP SYN+ACK and wider TCP flag counters
- directional captured-byte totals
- ALPN
- detailed TLS handshake characteristics
- retransmission / out-of-order state as filterable metadata
- arbitrary packet-content predicates
- unrecognized-packet filtering
- saved filter presets as part of the capture index
- `.filter` file parsing
- CLI / GUI integration

## Future Saved Filter Presets

Saved filter presets are a likely future product feature, for example:

- Large unknown UDP
- TLS without SNI
- VXLAN tenant 100
- Truncated large flows
- TCP flows containing resets

Presets should belong to application settings / user configuration, not capture
indexes.

## Open Questions

- Should "known / unknown detected protocol" be represented as a dedicated
  filter control, or only as inclusion/exclusion over `FlowProtocolHint` plus
  `unknown`?
- For Protocol Path predicates, should the first backend representation be a
  small tagged union of matching modes, or a normalized path predicate object
  that can carry multiple match shapes?
- Should captured-byte filtering be available immediately in all frontends once
  the aggregate exists, or staged after the backend/filter model is stabilized?
- For time filters, should the first shared backend contract use absolute
  microsecond timestamps only, leaving relative-to-capture-start translation to
  frontends?
- Should v1 include both include and exclude lists for every major family, or
  ship includes first and add exclusions where clearly useful?

## Risks To Resolve Before Implementation

- The shared filter contract must not blur canonical flow protocol, detected
  protocol hint, and service metadata. Each has different semantics and storage
  sources.
- Protocol Path matching must reuse existing normalized path identity rather
  than introducing a second incompatible path model.
- The implementation should avoid speculative aggregate sprawl. A compact,
  reviewable foundation is preferable to storing every imaginable future
  predicate source.
- Packet-level fields currently persisted in `PacketRef` still support existing
  index-only behavior. Any compaction plan must be paired with an explicit
  product-level decision about what index-only packet/stream semantics are still
  guaranteed.
