# Advanced Flow Filter RFC

Status: implemented backend/compiler/evaluator foundation with current
`.filter` v3 parse/format support, metadata-backed predicate coverage, current
`flows --adv-filter` CLI integration, current Qt Advanced Filter UI/workflow,
and current Tauri parity for the implemented Time and directional-traffic
surface.

This document defines the product and semantic filter model for the Advanced
Flow Filter in Pcap Flow Lab.

The current implementation keeps a separate structured filtering subsystem
without changing legacy text-filter behavior, index serialization, or the
existing frontend-neutral semantic path.

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

The implemented semantic foundation remains intentionally separate from the
lightweight legacy `FlowQuery` / `--filter` text-filter path.

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

CLI usage is intentionally conceptually distinct:

- `--filter "QUIC"` for the legacy text filter
- `--adv-filter <filter-file>` for the structured Advanced Flow Filter

Those modes are mutually exclusive. Advanced Flow Filter remains separate from
legacy `FlowQuery`: the CLI parses the `.filter` file into an
`AdvancedFlowFilterDocument`, projects the effective
`AdvancedFlowFilterSpec`, compiles/evaluates that effective spec against
canonical flow metadata, and only then reuses the ordinary `flows`
sort/limit/export path on the resulting canonical flow indices.

The current implementation now also defines the current development text
contract for Advanced Flow Filter documents:

```text
AdvancedFlowFilterDocument
    <-> parse/format current text format v3
    -> make_effective_advanced_flow_filter_spec(document)
AdvancedFlowFilterSpec
CompiledAdvancedFlowFilter
    -> evaluate
AdvancedFlowFilterResult
```

The text contract is a serialization layer for the configured document. It is
intentionally separate from filter compilation/evaluation and from any future
UI editor workflow.

## Current CLI Integration

The implemented CLI surface is:

```text
pcap-flow-lab flows <input> --adv-filter <path> [flow selection] [sort/limit/output options]
```

Current rules:

- `--filter` and `--adv-filter` are mutually exclusive.
- `--flow-number` and `--flow-numbers` remain candidate-scope selectors.
- `--sort`, `--limit`, and `--out-flows-list` remain CLI presentation/export
  concerns rather than part of the `.filter` file grammar.
- `.filter` files contain only Advanced Flow Filter semantics.
- Raw captures and compatible indexes both use the same metadata-backed
  evaluator after open/import completes.
- Ordinary evaluation does not require source packet bytes.

## Current Text Format v3

The current development text format is line-oriented and UTF-8 friendly.

Advanced Flow Filter has not yet shipped as a released public/stable product
feature. Therefore development versions of the `.filter` text format do not
currently require backward compatibility.

During pre-release development:

- `format_version` may be incremented whenever the design requires an
  incompatible format change
- only the current development format version needs to be readable
- previous experimental/development format versions may become unsupported
  immediately
- migration readers or compatibility branches are not required solely for
  unreleased `.filter` versions
- old development grammar does not need to be preserved merely because it once
  used an earlier unreleased `format_version`
- only the final format version selected for the first release containing
  Advanced Flow Filter becomes the compatibility baseline

Backward-compatibility policy for released `.filter` files will be defined
separately once the format actually ships.

- A UTF-8 BOM is accepted at the beginning of the file.
- Line endings may be `LF` or `CRLF`.
- `#` starts a comment outside quoted strings.
- Blank lines are ignored.
- The first meaningful line must be:

```text
format_version = 3
```

- `format_version` may appear only once.
- Any filter predicate before `format_version` is an error.
- Keys are ASCII and use canonical lowercase spellings.
- Enum-like values are ASCII and case-insensitive on input.
- boolean section-enabled values accept `true` and `false`, case-insensitively
  on input
- Formatter output is canonical, lowercase where applicable, strips comments,
  and always emits `format_version = 3` first.

Each non-comment assignment is:

```text
<key> = <value>
```

The first `=` outside quoted strings is the assignment separator. Any later
`=` characters belong to the value.

The parser returns `AdvancedFlowFilterTextParseResult` with:

- `status`
- parsed `AdvancedFlowFilterDocument`
- optional structured `issue` carrying line, optional column, key, token, and
  diagnostic message

The formatter returns `AdvancedFlowFilterTextFormatResult` with:

- `status`
- canonical serialized text
- optional structured `issue` when the configured document cannot be represented
  faithfully

Scalar keys are unique within one file. Repeating a scalar key such as
`packet_count.min` is an error. Repeated include/exclude predicates remain
legal and preserve order inside their category.

The text format now serializes the configured document model rather than only
the effective evaluator input:

- configured predicates are always preserved, including predicates in disabled
  sections
- section Enabled states are persisted independently
- evaluation still uses:

```text
parse configured document
    ->
make_effective_advanced_flow_filter_spec(document)
    ->
compile_advanced_flow_filter(...)
    ->
evaluate_advanced_flow_filter(...)
```

All sections default to Enabled = `true`. Canonical formatting omits default
`true` section assignments and emits only the non-default `false` assignments.

Canonical top-level ordering is:

1. `format_version`
2. non-default section Enabled assignments in fixed section order
3. configured predicates in canonical predicate order

### Grammar shape

The implemented v3 keys are:

```text
section.address_family.enabled = true | false
section.flow_protocol.enabled = true | false
section.detected_protocol.enabled = true | false
section.tls_version.enabled = true | false
section.quic_version.enabled = true | false
section.directionality.enabled = true | false
section.ports.enabled = true | false
section.ip_addresses.enabled = true | false
section.time.enabled = true | false
section.traffic.enabled = true | false
section.service.enabled = true | false
section.protocol_path.enabled = true | false
section.contains_layer.enabled = true | false

address_family.include = ipv4 | ipv6
address_family.exclude = ipv4 | ipv6

flow_protocol.include = <protocol>
flow_protocol.exclude = <protocol>

detected_protocol.include = <hint>
detected_protocol.exclude = <hint>

tls_version.include = <tls_version>
tls_version.exclude = <tls_version>

quic_version.include = <quic_version>
quic_version.exclude = <quic_version>

directionality.include = <directionality>
directionality.exclude = <directionality>

port.<either|a|b>.include = <port-or-range>
port.<either|a|b>.exclude = <port-or-range>

ip.<either|a|b>.include = <ipv4-exact-or-cidr> | <ipv6-exact-or-cidr>
ip.<either|a|b>.exclude = <ipv4-exact-or-cidr> | <ipv6-exact-or-cidr>

time.start.from = "<utc-timestamp>"
time.start.to = "<utc-timestamp>"
time.end.from = "<utc-timestamp>"
time.end.to = "<utc-timestamp>"
time.overlap.from = "<utc-timestamp>"
time.overlap.to = "<utc-timestamp>"
time.duration.min = <duration-quantity>
time.duration.max = <duration-quantity>

service.state.include = known | unknown
service.state.exclude = known | unknown
service.<equals|starts_with|contains>.<ci|cs>.include = <quoted-string>
service.<equals|starts_with|contains>.<ci|cs>.exclude = <quoted-string>

protocol_path.<exact|prefix|contains>.include = <protocol-path-value>
protocol_path.<exact|prefix|contains>.exclude = <protocol-path-value>

packet_count.<min|max> = <uint64>
original_bytes.<min|max> = <byte-quantity>
captured_bytes.<min|max> = <byte-quantity>
traffic.packet_distribution.include = mostly_a_to_b | balanced | mostly_b_to_a
traffic.packet_distribution.exclude = mostly_a_to_b | balanced | mostly_b_to_a
traffic.data_distribution.include = mostly_a_to_b | balanced | mostly_b_to_a
traffic.data_distribution.exclude = mostly_a_to_b | balanced | mostly_b_to_a
traffic.a_to_b.packet_count.<min|max> = <uint64>
traffic.b_to_a.packet_count.<min|max> = <uint64>
traffic.a_to_b.original_bytes.<min|max> = <byte-quantity>
traffic.b_to_a.original_bytes.<min|max> = <byte-quantity>
fragmented_packet_count.<min|max> = <uint64>
truncated_packet_count.<min|max> = <uint64>
tcp_syn_count.<min|max> = <uint64>
tcp_fin_count.<min|max> = <uint64>
tcp_rst_count.<min|max> = <uint64>
max_original_packet_length.<min|max> = <packet-byte-quantity>
max_captured_packet_length.<min|max> = <packet-byte-quantity>
```

`contains` Protocol Path predicates must contain exactly one layer.

The fixed section-order used for canonical non-default Enabled assignments is:

1. `address_family`
2. `flow_protocol`
3. `detected_protocol`
4. `tls_version`
5. `quic_version`
6. `directionality`
7. `ports`
8. `ip_addresses`
9. `traffic`
10. `service`
11. `protocol_path`
12. `contains_layer`

`protocol_path.contains.*` remains the configured predicate representation for
Contains Layer rules. `section.protocol_path.enabled` independently controls
`exact_path` and `path_prefix`, while `section.contains_layer.enabled`
independently controls `contains_layer` predicates during effective-spec
projection. The formatter still serializes all configured protocol-path
predicates regardless of either section state.

At evaluation time these configured predicates do not form one flat OR family.
They compile into two logical groups:

- Protocol Path group: `exact_path` and `path_prefix`
- Contains Layer group: `contains_layer`

Within each group, include predicates use OR and matching excludes reject.
Between the two groups, the evaluator uses AND.

### Canonical tokens

The current canonical formatter emits:

- flow protocol:
  - `unknown`
  - `icmp`
  - `igmp`
  - `tcp`
  - `udp`
  - `esp`
  - `icmpv6`
  - `sctp`
  - `arp`
- detected protocol:
  - `unknown`
  - `tls`
  - `http`
  - `dns`
  - `quic`
  - `ssh`
  - `stun`
  - `bittorrent`
  - `dhcp`
  - `mdns`
  - `smtp`
  - `pop3`
  - `imap`
  - `igmp`
  - `igmpv1`
  - `igmpv2`
  - `igmpv3`
- TLS version:
  - `unknown`
  - `tls1_2`
  - `tls1_3`
- QUIC version:
  - `unknown`
  - `v1`
  - `draft29`
  - `v2`
- address family:
  - `ipv4`
  - `ipv6`
- directionality:
  - `unidirectional`
  - `bidirectional`
- endpoint scope:
  - `either`
  - `a`
  - `b`
- service case:
  - `ci`
  - `cs`
- Protocol Path match kind:
  - `exact`
  - `prefix`
  - `contains`

### Numeric units

Implemented byte units:

- bare bytes for `original_bytes`, `captured_bytes`, and packet-length fields
- explicit `B`
- `KiB`
- `MiB`
- `GiB`
- `TiB`

Decimal SI byte suffixes such as `MB` are rejected.

Implemented duration units:

- `us`
- `ms`
- `s`
- `m`
- `h`

Formatter output is canonical:

- bytes use the largest exact binary unit, otherwise `B`
- durations use the largest exact supported unit, otherwise `us`

### Service strings

Service text predicates use quoted strings.

Supported escapes are:

- `\\`
- `\"`
- `\n`
- `\r`
- `\t`

Unterminated quotes and unknown escapes are parse errors.

### Protocol Path text mapping

The current Protocol Path v1 text uses the repository's canonical layer labels:

- `EthernetII`
- `IEEE 802.3`
- `LLC/SNAP`
- `LinuxSll`
- `LinuxSll2`
- `VLAN`
- `MPLS`
- `MPLS PW`
- `PBB`
- `PPPoE`
- `PPP`
- `MACsec`
- `IPv4`
- `IPv6`
- `TCP`
- `UDP`
- `SCTP`
- `ICMP`
- `ICMPv6`
- `ARP`
- `VXLAN`
- `Geneve`
- `GTP-U`
- `GRE`
- `AH`
- `ESP`

Identifier-bearing layers use:

- `VLAN(vid=<decimal>)`
- `MPLS(label=<decimal>)`
- `PBB(isid=<decimal-or-0x...>)`
- `VXLAN(vni=<decimal>)`
- `Geneve(vni=<decimal>)`
- `GTP-U(teid=<decimal-or-0x...>)`
- `GRE(key=<decimal-or-0x...>)`
- `AH(spi=<decimal-or-0x...>)`
- `ESP(spi=<decimal-or-0x...>)`

Formatter output uses canonical layer labels and canonical identifier names.
It rejects unrepresentable combinations such as a mismatched identifier kind on
the wrong layer.

### Canonical formatting order

The formatter emits categories in this stable order:

1. `format_version`
2. Protocol Path include, then exclude
3. Address Family include, then exclude
4. flow protocol include, then exclude
5. detected protocol include, then exclude
6. TLS version include, then exclude
7. QUIC version include, then exclude
8. ports include, then exclude
9. aggregate scalar predicates in fixed key order
10. directionality include, then exclude
11. IPv4 include
12. IPv6 include
13. IPv4 exclude
14. IPv6 exclude
15. service include, then exclude

The canonical formatter does not preserve:

- comments
- blank lines
- original key casing
- original enum token casing
- original cross-family `ip.*` interleaving

Semantic round-tripping is through `AdvancedFlowFilterSpec`, not through
preserving source layout.

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
- QUIC/TLS version hints already exist on canonical connections and are
  serialized in the current stable index format.
- Captured-byte totals, time bounds, TCP SYN/FIN/RST counts, and packet-size
  extrema now exist as compact per-connection aggregate metadata in
  `ConnectionAggregateStats`.

## Current Implemented Predicate Families

The initial backend stage supports these predicate families:

- Protocol Path
- Address Family (`FlowAddressFamily`)
- flow protocol (`ProtocolId`)
- detected protocol (the current user-facing Advanced Flow Filter subset of
  `FlowProtocolHint`)
- TLS version (`TlsVersionHint`)
- QUIC version (`QuicVersionHint`)
- IPv4 exact-address and CIDR predicates
- IPv6 exact-address and CIDR predicates
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

In the current backend stage, exact IP-address predicates compile to the same
normalized backend representation as full-width CIDR predicates:

- IPv4 exact -> `/32`
- IPv6 exact -> `/128`

Address predicates use canonical endpoint scope:

- either endpoint
- endpoint A
- endpoint B

TLS/QUIC version predicates use authoritative connection-level hint metadata.
They do not require packet rescans, and non-TLS/non-QUIC flows do not satisfy
version include predicates merely because their stored version enum is
`unknown`.

## Broader Product Model And Future Extensions

The current backend stage already implements the core predicate families
described earlier in this RFC, including IP/CIDR, ports, service predicates,
packet/byte ranges, Protocol Path predicates, TLS/QUIC versions, packet-size
aggregates, duration, and current directionality.

This section captures the broader product model and genuinely future
extensions beyond that implemented baseline.

### IP addresses and networks

Already implemented baseline:

- multiple IPv4/IPv6 addresses
- CIDR networks
- endpoint scope:
  - either endpoint
  - endpoint A
  - endpoint B

Future extension:

- future "between two networks" semantics

### Ports

Already implemented baseline:

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

Already implemented baseline:

- known / unknown service recognition predicates
- equals / starts-with / contains text predicates
- include / exclude support

Service is one deliberate structured exception inside the filter model.

Include evaluation uses two optional subgroups:

- recognition predicates:
  - `known`
  - `unknown`
- text predicates:
  - `equals`
  - `starts_with`
  - `contains`

Composition is:

- OR within recognition
- OR within text
- AND between recognition and text

So:

- no Service include predicates means Service imposes no restriction
- `known + contains("example")` means recognized AND containing `example`
- `known + unknown` with no text rules is effectively no Service restriction

Exclude remains simple OR rejection:

- matching any recognition exclusion rejects
- matching any text exclusion rejects

Future extension:

- regex matching

### Flow packet count

Already implemented baseline:

- minimum and/or maximum packet count

### Flow byte volume

Already implemented baseline:

- original bytes: minimum and/or maximum
- captured bytes: minimum and/or maximum

### Protocol Path

Already implemented baseline:

- multiple path predicates

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

Longer-term UI/product intent:

- a dedicated "Add Protocol Path..." selector should create the same backend
  predicate type used by the common filter model
- Statistics -> Show flows should eventually emit the same common Protocol Path
  predicate instead of maintaining a separate filtering mechanism

### Protocol-specific versions

Already implemented baseline:

- TLS 1.2
- TLS 1.3
- QUIC v1
- QUIC v2
- currently represented draft versions
- unavailable / unknown where meaningful

### Packet-size aggregates

Already implemented baseline:

- largest original packet length
- largest captured packet length

Future extension:

- minimum packet-size predicates

### Packet/flow conditions

Already implemented baseline:

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

Already implemented baseline:

- flow start bounds:
  - `time.start.from`
  - `time.start.to`
- flow end bounds:
  - `time.end.from`
  - `time.end.to`
- flow lifetime overlap bounds:
  - `time.overlap.from`
  - `time.overlap.to`
- duration bounds:
  - `time.duration.min`
  - `time.duration.max`

Time uses the current authoritative connection aggregates:

- `first_timestamp_us`
- `last_timestamp_us`

No packet rescanning is required.

All implemented time bounds are inclusive.

Start:

- `time.start.from = A` means `first_timestamp >= A`
- `time.start.to = B` means `first_timestamp <= B`

End:

- `time.end.from = A` means `last_timestamp >= A`
- `time.end.to = B` means `last_timestamp <= B`

Lifetime overlap:

- `time.overlap.from = A` alone means `last_timestamp >= A`
- `time.overlap.to = B` alone means `first_timestamp <= B`
- both together mean:
  - `first_timestamp <= B`
  - `last_timestamp >= A`

Duration remains:

- `last_timestamp - first_timestamp`

So a one-packet connection naturally has zero duration.

The current implementation uses absolute UTC timestamps with `Z` and up to
microsecond precision. Canonical formatting uses six fractional digits, for
example `2026-03-22T12:27:32.000000Z`.

Future extension:

- relative-to-capture-start time as a later secondary UI mode
- local-time / offset timestamp input

### Directionality

Already implemented baseline:

- current backend predicate values:
  - unidirectional
  - bidirectional

Current user-facing wording is:

- `Only A -> B packets`
- `Packets in both directions`

Where `A -> B` means the direction of the first observed packet in that
canonical flow. It does not imply client/server or request/response roles.

### Packet distribution

Already implemented baseline:

- include / exclude values:
  - `mostly_a_to_b`
  - `balanced`
  - `mostly_b_to_a`

This classification uses directional packet counts and shares the same
`DirectionDistribution` boundary semantics used by Flow Analysis:

- exactly `2:1` is still `balanced`
- one side becomes `mostly_*` only when it exceeds the other side by more than
  `2x`

Examples:

- `20 : 10` -> `balanced`
- `21 : 10` -> `mostly_a_to_b`

### Data distribution

Already implemented baseline:

- include / exclude values:
  - `mostly_a_to_b`
  - `balanced`
  - `mostly_b_to_a`

This classification uses directional original-byte totals, not transport
payload, application payload, or captured-byte totals.

It uses the same `DirectionDistribution` boundary semantics described above.

### Directional traffic ranges

Already implemented baseline using canonical A/B orientation:

- A->B packet count
- B->A packet count
- A->B original bytes
- B->A original bytes
- Packet distribution
- Data distribution

If the reverse direction was never observed:

- `B -> A` packet count = `0`
- `B -> A` original bytes = `0`

### Derived rate predicates

Future extension where source aggregates are sufficient:

- average packets/sec
- average original-byte data rate

These should be derived in O(1) from stored aggregates and not persisted as
independent long-lived metadata.

## Fixed Execution Order

The declarative filter specification does not define hot-path execution order.

The current backend stage uses this fixed execution order:

1. initial candidate scope
2. Address Family
3. Protocol Path membership
4. flow protocol / detected protocol / TLS version / QUIC version
5. ports
6. cheap numeric / aggregate predicates and directionality
7. IP address / CIDR predicates
8. service predicates

Service matching is deliberately last.

Protocol Path predicates are resolved during compile to dense
`ProtocolPathId` membership tables derived from the session's
`ProtocolPathRegistry`.

This compile step partitions the configured `protocol_path` family into:

- a Protocol Path membership group for `exact_path` and `path_prefix`
- a Contains Layer membership group for `contains_layer`

Each group keeps its own include/exclude membership tables.

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

There are two intentional structured exceptions:

- Protocol Path: configured `protocol_path` predicates are stored together, but
  the evaluator treats Protocol Path (`exact_path` / `path_prefix`) and
  Contains Layer (`contains_layer`) as two independent groups combined with
  AND.
- Service: include uses OR within recognition, OR within text, and AND between
  those two subgroups. Exclude remains any-match rejection across both
  subgroup types.

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
- TLS version hint
- QUIC version hint

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

This now covers:

- Time bounds from persisted first/last timestamps
- directional packet and original-byte ranges from `flow_a` / `flow_b`
  aggregates
- packet/data distribution from the shared `DirectionDistribution`
  classification

Evaluation remains constant-time per candidate connection. It does not require:

- `PacketRef` traversal
- source capture rereads
- packet-byte reads
- reassembly
- new index v15 fields

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

- For time filters, should the first shared backend contract use absolute
  microsecond timestamps only, leaving relative-to-capture-start translation to
  frontends?

## Remaining Risks And Design Constraints

- The shared filter contract must not blur canonical flow protocol, detected
  protocol hint, and service metadata. Each has different semantics and storage
  sources.
- Protocol Path matching must reuse existing normalized path identity rather
  than introducing a second incompatible path model.
- The implementation should avoid speculative aggregate sprawl. A compact,
  reviewable foundation is preferable to storing every imaginable future
  predicate source.
