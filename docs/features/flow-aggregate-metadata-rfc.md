# Flow Aggregate Metadata RFC

Status: implemented in the current production/runtime and stable v15 index path.

This document records the current compact aggregate-metadata foundation used by
Pcap Flow Lab for connection-level analysis and the final compact persistent
`PacketRef` model that now accompanies it.

Related RFCs:

- [Advanced Flow Filter RFC](advanced-flow-filter-rfc.md)
- [Index v15 Container RFC](index-v15-container-rfc.md)

## Goal

The aggregate foundation exists to support flow-level analysis and future
index-backed metadata queries without repeatedly rescanning persisted packet
metadata for facts that are already authoritative at the canonical connection
level.

The resulting design is:

- canonical aggregate ownership remains on `ConnectionV4` / `ConnectionV6`
- stable v15 persists compact authoritative connection aggregates
- persistent `PacketRef` is now a compact locator/ordering record only
- packet-level transport payload length, TCP flags, and fragmentation state are
  transient decoded facts rather than persisted packet-ref fields

## Current Persistent PacketRef

Persistent `PacketRef` now retains only durable locator/ordering metadata:

- `packet_index`
- `ts_sec`
- `ts_usec`
- `byte_offset`
- `data_link_type`
- `captured_length`
- `original_length`

It intentionally no longer stores:

- transport payload length
- TCP flags
- IP fragmentation state

### Stable v15 PacketRef wire layout

The stable serialized `PacketRef` payload is now exactly:

1. `u64 packet_index`
2. `u32 ts_sec`
3. `u32 ts_usec`
4. `u64 byte_offset`
5. `u32 data_link_type`
6. `u32 captured_length`
7. `u32 original_length`

Serialized size:

- exactly 36 bytes per packet ref

### Runtime PacketRef size

In-memory `sizeof(PacketRef)` remains ABI- and compiler-dependent because the
project intentionally does not use packed structs for this type.

Capture Storage Diagnostics remains the authoritative runtime verification
surface for `sizeof(PacketRef)`.

Typical x64 builds may report roughly 40 bytes, but that is not a wire-format
or ABI contract.

## Current Aggregate Foundation

The current aggregate foundation is owned directly by canonical
`ConnectionV4` / `ConnectionV6` state and persisted by the stable v15 index.

Implemented authoritative connection facts include:

- first/last timestamps
- captured-byte totals
- truncated-packet count
- maximum original packet length
- maximum captured packet length
- TCP SYN/FIN/RST counts
- fragmented-packet count
- `has_fragmented_packets`
- `protocol_hint`
- `service_hint`
- `quic_version`
- `tls_version`

Directional packet counts and directional original-byte totals remain owned by
the directional `FlowV4` / `FlowV6` structures.

## Transient Packet Metadata

Packet-level transport payload length, TCP flags, and fragmentation state are
now treated as transient decoded facts.

Current transient ownership is split by layer:

- core import/decode uses `PacketImportMetadata`
- source-backed app/session presentation uses
  `session_detail::TransientPacketDerivedMetadata`

`PacketImportMetadata` carries only the import-time facts that connection
ingestion still needs:

- optional captured transport payload length
- optional TCP flags
- IP fragmentation state

These facts are passed transiently through import/decode and
`Connection::add_packet(...)`; they are not persisted in `PacketRef`.

## Source-Backed vs Index-Only Semantics

### Source-backed sessions

When source capture bytes are available:

- selected-flow packet lists derive payload length, TCP flags, and
  fragmentation from packet bytes
- selected-packet Summary/Bytes, checksum behavior, reassembly, TLS, QUIC, and
  stream helpers derive packet-level facts from authoritative bytes
- bounded selected-flow context may still contribute reconstructed/derived
  packet-adjacent views where explicitly supported

### Index-only sessions

When source capture bytes are unavailable:

- packet-level payload length is unavailable
- packet-level TCP flags are unavailable
- packet-level fragmentation state is unavailable

These unavailable states are now explicit product semantics. The application
does not silently coerce them to zero or false.

Flow-level authoritative behavior is preserved through connection aggregates,
including:

- TCP SYN/FIN/RST counts
- fragmented-packet count
- captured/original byte totals
- protocol/service/TLS/QUIC aggregate hints

## FlowAnalysis Ownership Boundary

FlowAnalysis now uses authoritative `ConnectionAggregateStats` for the
migrated connection-level metrics, including:

- captured-byte totals
- first/last timestamp bounds and duration
- TCP SYN/FIN/RST counts
- maximum original packet length
- maximum captured packet length

FlowAnalysis still intentionally derives full-flow order-sensitive outputs from
ordered packet collections where that is semantically required, such as:

- packet-size histograms
- inter-arrival/gap/burst calculations
- rate-graph generation
- sequence preview rows

Sequence preview rows should not be interpreted as proving that persistent
packet-level payload length still exists. Packet-level preview payload details
now depend on source-backed packet-byte authority rather than persisted
`PacketRef` fields.

## Size Impact

Persistent packet-ref compaction is now active.

Serialized saving per packet ref:

- previous serialized packet ref: 42 bytes
- current serialized packet ref: 36 bytes
- saving: 6 bytes per persisted packet ref

This saving applies anywhere the stable index payload serializes `PacketRef`
records.

## Compatibility Notes

The stable outer container remains:

- `container_format_version = 1`
- `index_revision = 15`

Packet-ref compaction changed only the payload schemas of the section families
that serialize `PacketRef`. Those section-family details are recorded in the
[Index v15 Container RFC](index-v15-container-rfc.md).
