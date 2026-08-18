# Index v15 Container RFC

Status: stable v15 container is active in the production reader/writer.

This document defines the frozen container-level baseline for the active stable
index v15 format.

Production now writes stable-container v15 indexes, loads stable v15+ indexes
that retain the supported core section schemas, and inspects legacy v14
headers while rejecting legacy full-load with a rebuild-required diagnostic.

Related RFCs:

- [Advanced Flow Filter RFC](advanced-flow-filter-rfc.md)
- [Flow Aggregate Metadata RFC](flow-aggregate-metadata-rfc.md)

## Goal

Starting with index v15, a future Pcap Flow Lab version should be able to read
the stable index preamble/header and report useful metadata even if it cannot
load the analysis payload.

The new compatibility contract starts at v15.

v14 and earlier may remain unsupported.

## Current State

### Historical v14 top-level structure

Verified from current code:

- file starts with:
  - `u64 kLegacyCaptureIndexMagic`
  - `u16 kLegacyCaptureIndexVersion`
  - `u16 reserved`
- historical legacy version constant is `kLegacyCaptureIndexVersion = 14`
- after the fixed preamble, the file contains length-delimited sections:
  - `u32 section_id`
  - `u64 payload_size`
  - raw payload bytes

Historical section families were:

- `source_info`
- `summary`
- `protocol_paths`
- `ipv4_connections`
- `ipv6_connections`
- `unrecognized_packets`
- `packet_locator`

### Current production reader behavior

Verified current behavior:

- reader recognizes both legacy and stable container magic values
- legacy v14 indexes are inspectable at the header/version level
- legacy v14 full-load is rejected with:
  - `"legacy index version 14 is no longer loadable; rebuild the index from the source capture"`
- stable v15+ load is gated primarily by container version plus required
  section/schema support, not by exact global revision equality
- unknown required sections are rejected
- unknown optional sections are skipped by payload size
- the stable core sections remain required in practice

### Current source metadata availability

Current source metadata already exists as `CaptureSourceInfo` and contains:

- source capture path
- source format
- source file size
- source last-write time
- source content fingerprint

In production stable v15, this metadata now lives in the stable header rather
than a required payload `source_info` section.

## Frozen v15 Baseline

v15 should establish a stable self-describing container design.

The main compatibility rule is:

- a future reader may reject unsupported analysis payload sections
- but it should still be able to read and report stable header metadata

At minimum, a future reader should be able to determine:

- this is a Pcap Flow Lab index
- container format version
- index/schema revision
- writer application version
- source capture path/name
- source capture format
- source capture file size
- source last-write metadata if retained
- source fingerprint/identity if retained

Frozen initial container identity:

- stable-container magic is distinct from the legacy v14-and-earlier magic
- `container_format_version = 1`
- `index_revision = 15`

These have different semantics:

- `container_format_version` identifies the stable outer framing/header
  contract and should change rarely
- `index_revision` is diagnostic metadata describing the Pcap Flow Lab index
  generation/revision
- `index_revision` is not the primary compatibility gate
- future payload compatibility should primarily depend on section id plus
  section schema version

## Proposed Conceptual Layout

### Stable preamble/header

The stable v15 header uses little-endian integral encoding, UTF-8
length-prefixed strings with no required trailing NUL, and a serialized layout
that does not depend on C++ struct padding or host ABI.

The frozen field order is:

- `u64 magic`
- `u16 container_format_version`
- `u16 header_flags`
- `u32 header_size`
- `u32 index_revision`
- `u32 writer_application_version_length`
- `writer_application_version` UTF-8 bytes
- `u8 source_capture_format`
- `u64 source_file_size`
- `i64 source_last_write_time`
- `u64 source_content_fingerprint`
- `u32 source_capture_path_length`
- `source_capture_path` UTF-8 bytes
- optional append-only stable-header tail bytes up to `header_size`

The writer application version is stored as a UTF-8 string. In production, the
writer source is `PFL_APP_VERSION`.

### After the stable header

The payload should be organized as versioned length-delimited sections.

Each section uses this exact header:

- `u32 section_id`
- `u16 section_schema_version`
- `u16 section_flags`
- `u64 payload_size`

This is an exact 16-byte wire header, followed immediately by `payload_size`
payload bytes.

This keeps unknown/optional data skippable and known data explicitly versioned.

## Required vs Optional Sections

### Required section semantics

Required sections are necessary to interpret the analysis payload correctly.

If a required section is missing or has an unsupported schema version:

- analysis payload loading should fail cleanly
- stable header metadata should still remain available for diagnostics

Section flag bit 0 is frozen as:

- `REQUIRED = 0x0001`

### Optional section semantics

Optional sections can be skipped safely when unknown or unsupported.

Desired behavior:

- unknown optional section -> skip by payload size
- known supported section version -> read
- unsupported optional section version -> ignore if safe to do so

The file-provided REQUIRED bit is not the only source of truth. A future reader
must still validate the known-core-section presence/cardinality rules required
by the v15 schema.

## Compatibility Contract Starting At v15

The proposed long-term compatibility model is:

- stable header is the guaranteed introspection surface
- payload compatibility is determined mainly by required section schema versions
- a global index/container revision may remain useful for diagnostics and broad
  format families, but not as the sole compatibility gate

This means future revisions do not need universal full backward compatibility.

The important improvement is controlled section-level compatibility and better
diagnostics.

## Proposed Failure Behavior

When the reader cannot load the analysis payload:

- it should still report stable source metadata from the header
- it should explain which required section or required section schema version is
  unsupported
- it should not fail with only a generic exact-version rejection when header
  metadata is still readable

Examples of useful diagnostics:

- recognized Pcap Flow Lab index container
- writer application version
- source capture path / format / size
- unsupported required section id
- unsupported section schema version

## Header Size And Append-Only Extension

`header_size` is useful because it allows:

- a reader to skip forward to the first section even if the stable header grows
- append-only extension of header fields in later revisions
- preservation of the stable preamble contract while allowing new stable header
  metadata to be added in a controlled way

Frozen `header_size` semantics:

- `header_size` is the total encoded stable-header byte count up to the first
  payload section
- a future reader may parse the known stable-header prefix and skip unknown
  append-only bytes until `header_size`
- fields may be extended only append-only within the same compatible
  container-format generation
- malformed `header_size` values must be rejected safely

## Current v14/v15 Boundary

This RFC still does not require:

- a v14 -> v15 compatibility loader
- automatic rewriting of old indexes
- support for all historical index revisions

For v14 and earlier, current behavior is:

- inspectable legacy header/version recognition
- full-load rejection with a rebuild-required diagnostic

The compatibility/introspection contract begins at stable v15.

## Current-State Gaps This RFC Resolved

The old v14 format had these issues:

- exact global version gating happens before source metadata can be read
- unknown sections are always fatal
- section payloads have ids and sizes but no explicit per-section schema
  versions
- there is no stable header-level writer application version
- there is no stable header-level source metadata contract

## Frozen Initial Section Families

The initial core data families remain:

- summary
- protocol-path registry
- IPv4 connections
- IPv6 connections
- unrecognized packets
- packet locator

Basic source identity is not duplicated into a required payload `source_info`
section. The stable header is the authoritative baseline source-introspection
surface.

Cardinality contract:

- IPv4 connection sections are repeatable/chunkable
- IPv6 connection sections are repeatable/chunkable
- the other initial core sections are singleton unless explicitly revised later

## Remaining Open Questions

- Which future optional/source-details fields, if any, should live outside the
  stable header?
- Should the stable header later include a short source basename in addition to
  full path for diagnostics?
- Should connection-data sections be subdivided further in future revisions?
- Should the packet locator remain required in future schemas, or become
  optional if some features can degrade gracefully?

## Risks To Resolve Before Production Implementation

- If the stable header is underspecified, v15 may still force future versions
  into broad exact-version rejections.
- If section compatibility rules are unclear, optional/required handling can
  become inconsistent across reader implementations.
- If source metadata is split awkwardly between stable header and sections,
  diagnostics may remain incomplete in partial-compatibility scenarios.
- If global revision and per-section schema versions overlap ambiguously, future
  migrations will be harder to reason about.
