# Advanced Flow Filter RFC

Status: proposed design / RFC only.

This document defines the planned product and backend-filter model for a future
Advanced Flow Filter in Pcap Flow Lab.

This pass does not implement the filter, does not change current index
serialization, and does not change runtime query behavior.

Related RFCs:

- [Flow Aggregate Metadata RFC](flow-aggregate-metadata-rfc.md)
- [Index v15 Container RFC](index-v15-container-rfc.md)

## Goal

The future Advanced Flow Filter should operate on canonical flows/connections
and indexed metadata.

Normal filter evaluation must not require rescanning the source capture or
re-running expensive packet dissection just to answer an ordinary flow query.

Unrecognized packets are not canonical flows and are outside the initial
Advanced Flow Filter scope.

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

Verified current-state facts from code:

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
  extrema are currently derived from `PacketRef` collections rather than stored
  as compact flow aggregates.

## Proposed V1 Filter Families

The initial filter family set is:

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
- unidirectional / bidirectional
- derived packet dominance / ratio
- derived byte dominance / ratio

### Derived rate predicates

Where source aggregates are sufficient:

- average packets/sec
- average original-byte data rate

These should be derived in O(1) from stored aggregates and not persisted as
independent long-lived metadata.

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

The following compact per-connection aggregates are proposed in
[Flow Aggregate Metadata RFC](flow-aggregate-metadata-rfc.md) because they are
currently recomputed by scanning packet refs:

- first timestamp
- last timestamp
- captured-byte total
- truncated-packet count
- max original packet length
- max captured packet length
- TCP SYN count
- TCP FIN count
- TCP RST count

The v1 filter should be implemented on top of that agreed aggregate foundation
rather than by repeatedly rescanning `PacketRef` vectors.

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
