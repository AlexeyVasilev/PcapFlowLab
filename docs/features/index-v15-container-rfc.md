# Index v15 Container RFC

Status: previous stable v15 container. Current production writes and loads the
stable v16 container; v15 full payload load is rebuild-required.

This document defines the frozen outer-container baseline for the previous
stable index v15 format and records the per-section schema families used by
the compact persistent `PacketRef` migration before the v16 cutover.

Related RFCs:

- [Advanced Flow Filter RFC](advanced-flow-filter-rfc.md)
- [Flow Aggregate Metadata RFC](flow-aggregate-metadata-rfc.md)

## Frozen Outer Container Identity

The stable outer container remains:

- magic: stable `PFLIDXV1`
- `container_format_version = 1`
- `index_revision = 15`

These values did not change during PacketRef compaction.

The compatibility model is:

- stable-header inspection is independent of payload compatibility
- full payload loading depends on required section families and their schema
  versions
- per-section schema evolution is preferred over globally bumping the outer
  stable container

## Stable Header

The stable v15 header remains an authoritative introspection surface for
recognizing previous stable indexes even though full v15 payload loading is no
longer supported by the current production reader.

It still provides:

- writer application version
- source capture format
- source file size
- source last-write time
- source content fingerprint
- source capture path

Header inspection continues to work even when full payload loading is rejected
because of unsupported section schemas.

## Stable Section Header

Every stable payload section continues to use the same 16-byte section header:

- `u32 section_id`
- `u16 section_schema_version`
- `u16 section_flags`
- `u64 payload_size`

Section flag bit 0 remains the required-section bit.

## Compact PacketRef Impact

Persistent `PacketRef` now serializes as a compact 36-byte payload:

1. `u64 packet_index`
2. `u32 ts_sec`
3. `u32 ts_usec`
4. `u64 byte_offset`
5. `u32 data_link_type`
6. `u32 captured_length`
7. `u32 original_length`

Removed from stable serialized `PacketRef`:

- transport payload length
- TCP flags
- IP fragmentation state

Any stable section family whose payload wire layout embeds serialized
`PacketRef` had to move to a new section schema version.

## Current Stable v15 Section Families

### Schema version 1 families (payload unchanged)

The following section families remain at schema version 1 because their payload
wire layout did not change:

- `summary`
- `protocol_paths`
- `packet_locator`

### Schema version 2 families (payload changed)

The following section families now use schema version 2 because their payload
serializes compact 36-byte `PacketRef` records instead of the older 42-byte
packet-ref payload:

- `ipv4_connections`
- `ipv6_connections`
- `unrecognized_packets`

These are the only stable section families that changed for the final compact
PacketRef stage.

## Writer Behavior

The production writer now emits:

- `summary` -> schema version 1
- `protocol_paths` -> schema version 1
- `ipv4_connections` -> schema version 2
- `ipv6_connections` -> schema version 2
- `unrecognized_packets` -> schema version 2
- `packet_locator` -> schema version 1

The outer stable container remains unchanged while these per-family schema
versions carry the payload-compatibility change.

## Reader Behavior

### Supported payload schemas

The production reader supports:

- schema version 1 for unchanged families
- schema version 2 for the compact-PacketRef affected families

### Temporary old v15 schema-1 affected payloads

The reader does not provide compatibility loading for temporary unreleased v15
payloads that still used the old schema-1 packet-ref layout in affected
section families.

If full payload loading encounters an affected section family with the older
legacy packet-ref layout, loading is rejected with a rebuild-required
diagnostic:

- `"stable index uses legacy packet-ref storage for packet metadata; rebuild the index from the source capture"`

This policy applies to the affected PacketRef-bearing stable section families.

### Stable-header inspection

Stable-header inspection still succeeds for those indexes because header
introspection is independent of payload compatibility.

## Legacy v14 Boundary

This compact-PacketRef change does not change the existing legacy-v14 policy.

Current behavior for legacy v14 remains:

- legacy v14 header/version recognition is inspectable
- legacy v14 full load is rejected with a rebuild-required diagnostic

The PacketRef compaction pass does not add any new v14 compatibility path.

## Previous Compatibility Summary

The previous stable v15 compatibility contract was:

- outer container format stays at version 1
- index revision stays at 15
- compact PacketRef is carried by per-section schema versions, not by a new
  outer container revision
- unchanged stable section families remain at schema version 1
- PacketRef-bearing stable section families now use schema version 2
- temporary old affected v15 schema-1 payloads are rebuild-required
- stable-header inspection remains available independent of full payload
  compatibility
